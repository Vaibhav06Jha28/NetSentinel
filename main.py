from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from threading import Thread
from typing import List
from datetime import datetime
from joblib import load
from pathlib import Path
import asyncio
import os

from app.sniffer import start_sniffing
from app.dashboard import router as dashboard_router
from app.websocket import router as ws_router, push_packet_to_clients
from utils.ip_reputation import check_ip_reputation
from app.store import packet_data, anomaly_alerts, live_packet_queue

# === FastAPI Setup ===
app = FastAPI()

# Serve static folder (unchanged)
app.mount("/static", StaticFiles(directory="static"), name="static")

# === Root route (serves dashboard.html) ===
@app.get("/", response_class=HTMLResponse)
async def root():
    html_file = Path("static/dashboard.html")
    if not html_file.exists():
        return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)
    return html_file.read_text(encoding="utf-8")

# === CORS Middleware ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Routers ===
app.include_router(dashboard_router)
app.include_router(ws_router)

# === Trusted/Blocked IPs ===
blocked_ips = set()
trusted_ips = set()
TRUSTED_IP_FILE = "trusted_ips.txt"

class IPRequest(BaseModel):
    ip: str

class IPListResponse(BaseModel):
    trusted_ips: List[str]

def load_trusted_ips(file=TRUSTED_IP_FILE):
    try:
        with open(file, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print("[!] trusted_ips.txt not found. Starting with empty list.")
        return set()

def save_trusted_ip(ip: str, file=TRUSTED_IP_FILE):
    with open(file, "a") as f:
        f.write(f"{ip}\n")

def remove_trusted_ip(ip: str, file=TRUSTED_IP_FILE):
    current = load_trusted_ips(file)
    current.discard(ip)
    with open(file, "w") as f:
        for item in sorted(current):
            f.write(f"{item}\n")

trusted_ips = load_trusted_ips()

# === API Routes ===
@app.post("/block_ip")
async def block_ip(data: IPRequest):
    blocked_ips.add(data.ip)
    print(f"[BLOCKED] {data.ip}")
    return JSONResponse({"status": "blocked", "ip": data.ip})

@app.get("/trusted_ips", response_model=IPListResponse)
async def get_trusted_ips():
    return {"trusted_ips": sorted(list(trusted_ips))}

@app.post("/trust_ip")
async def trust_ip(data: IPRequest):
    if data.ip not in trusted_ips:
        trusted_ips.add(data.ip)
        save_trusted_ip(data.ip)
        print(f"[TRUSTED] {data.ip} added to trust list.")
    return JSONResponse({"status": "trusted", "ip": data.ip})

@app.post("/untrust_ip")
async def untrust_ip(data: IPRequest):
    if data.ip in trusted_ips:
        trusted_ips.discard(data.ip)
        remove_trusted_ip(data.ip)
        print(f"[REMOVED] {data.ip} removed from trust list.")
    return JSONResponse({"status": "untrusted", "ip": data.ip})

@app.get("/simulate_malicious_ip")
async def simulate_malicious_ip():
    fake_ip = "194.87.237.1"
    timestamp = datetime.now().strftime("%H:%M:%S")

    data = {
        "timestamp": timestamp,
        "src": fake_ip,
        "dst": "192.168.1.5",
        "hostname_src": "malicious.example.com",
        "hostname_dst": "local.device",
        "proto": "TCP",
        "sport": 4444,
        "dport": 80,
        "length": 512,
        "app_proto": "HTTP",
        "country_src": "Russia",
        "country_dst": "India",
        "country_code_src": "ru",
        "country_code_dst": "in",
        "is_incoming": True,
        "alert_message": "⚠️ Simulated Malicious IP"
    }

    packet_data.append(data)
    live_packet_queue.append(data)
    anomaly_alerts.append({
        "timestamp": timestamp,
        "ip": fake_ip,
        "message": "Simulated malicious traffic detected"
    })

    try:
        asyncio.get_running_loop().create_task(push_packet_to_clients(data))
    except RuntimeError:
        asyncio.run(push_packet_to_clients(data))

    print(f"[🧪] Simulated malicious IP injected: {fake_ip}")
    return {"status": "simulated", "ip": fake_ip}

@app.get("/test_anomaly")
async def simulate_anomaly():
    import time
    fake_packet = {
        "src": "185.234.219.66",
        "dst": "192.168.1.10",
        "proto": "TCP",
        "length": 900,
        "is_incoming": True,
        "country_src": "Russia",
        "country_code_src": "RU",
        "timestamp": time.strftime("%H:%M:%S"),
        "alert_message": "⚠️ Simulated Malicious IP (demo)"
    }

    try:
        asyncio.get_running_loop().create_task(push_packet_to_clients(fake_packet))
    except RuntimeError:
        asyncio.run(push_packet_to_clients(fake_packet))

    return {"status": "sent"}

# === AI Model Load ===
try:
    isolation_model = load("models/isolation_model.pkl")
    print("🤖 Isolation Forest model loaded.")
except Exception:
    isolation_model = None
    print("⚠️ Failed to load isolation_model.pkl")

# === Packet Handler ===
def handle_packet(packet: dict):
    src_ip = packet.get("src")
    dst_ip = packet.get("dst")

    if src_ip in blocked_ips or dst_ip in blocked_ips:
        packet["alert_message"] = "🚫 Blocked IP Attempt"
    elif src_ip in trusted_ips or dst_ip in trusted_ips:
        pass
    else:
        rep_src = check_ip_reputation(src_ip)
        rep_dst = check_ip_reputation(dst_ip)

        if rep_src.get("is_malicious"):
            packet["alert_message"] = f"⚠️ Suspicious Source IP (fraud_score: {rep_src.get('fraud_score')})"
        elif rep_dst.get("is_malicious"):
            packet["alert_message"] = f"⚠️ Suspicious Destination IP (fraud_score: {rep_dst.get('fraud_score')})"

    if isolation_model:
        proto_code = {"TCP": 0, "UDP": 1, "ICMP": 2}.get(packet.get("proto"), -1)
        try:
            prediction = isolation_model.predict([[proto_code, packet.get("length", 0)]])
            if prediction[0] == -1:
                packet["alert_message"] = "⚠️ AI: Anomalous Packet Detected"
        except Exception as e:
            print(f"[AI ERROR]: {e}")

    if "alert_message" in packet:
        timestamp = datetime.now().strftime("%H:%M:%S")
        packet["timestamp"] = timestamp
        live_packet_queue.append(packet)
        anomaly_alerts.append({
            "timestamp": timestamp,
            "ip": packet.get("src"),
            "message": packet["alert_message"]
        })

        try:
            asyncio.get_running_loop().create_task(push_packet_to_clients(packet))
        except RuntimeError:
            asyncio.run(push_packet_to_clients(packet))

# === Start Sniffer Thread ===
# Use simulate_traffic if running in Railway (no live interface access)
Thread(target=start_sniffing, daemon=True).start()

# === Run App (For local only — Railway won't use this block) ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

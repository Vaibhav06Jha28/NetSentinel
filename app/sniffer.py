from scapy.all import sniff, IP, DNS, ICMP, get_if_list, get_if_addr
from scapy.layers.http import HTTPRequest
import socket
import geoip2.database
from datetime import datetime
from time import time
from collections import defaultdict
import os
import ipaddress
import csv
import joblib
import asyncio

from app.store import packet_data, anomaly_alerts, live_packet_queue
from app.ids import check_custom_rules
from utils.ip_reputation import check_ip_reputation
from app.websocket import push_packet_to_clients

# === Start memory profiling ===
import tracemalloc
tracemalloc.start()

# === Load GeoIP Database ===
try:
    geo_reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
    print("🌍 GeoIP database loaded.")
except Exception as e:
    print(f"❌ Failed to load GeoIP DB: {e}")
    geo_reader = None

# === Load Trusted IPs ===
TRUSTED_IPS_FILE = "trusted_ips.txt"
trusted_ips = set()
if os.path.exists(TRUSTED_IPS_FILE):
    with open(TRUSTED_IPS_FILE, "r") as f:
        trusted_ips = set(line.strip() for line in f if line.strip())
    print(f"✅ Loaded trusted IPs: {trusted_ips}")
else:
    print("⚠️ trusted_ips.txt not found. Proceeding without trusted IPs.")

# === Load AI Model ===
try:
    ai_model = joblib.load("models/isolation_model.pkl")
    print("🤖 AI model loaded.")
except Exception as e:
    ai_model = None
    print(f"⚠️ Failed to load AI model: {e}")

# === Interface Selection ===
def get_local_ips():
    try:
        hostname = socket.gethostname()
        return set(socket.gethostbyname_ex(hostname)[2])
    except:
        return {"127.0.0.1"}

def get_best_interface():
    local_ips = get_local_ips()
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip in local_ips and not ip.startswith("127."):
                print(f"🔧 Using interface: {iface} ({ip})")
                return iface
        except:
            continue
    fallback = get_if_list()[0]
    print(f"⚠️ Falling back to interface: {fallback}")
    return fallback

local_ips = get_local_ips()

# === GeoIP Lookup ===
def get_country_info(ip):
    if not geo_reader:
        return "Unknown", "xx"
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Private IP", "xx"
        if ip_obj.is_loopback:
            return "Loopback", "xx"
        if ip_obj.is_reserved:
            return "Reserved", "xx"

        city = geo_reader.city(ip)
        country = city.country.name or "Unknown"
        code = city.country.iso_code.lower() if city.country.iso_code else "xx"
        return country, code
    except Exception as e:
        print(f"[GeoIP ERROR] IP: {ip} | {e}")
        return "Unknown", "xx"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

# === DoS Detection ===
ip_packet_counts = defaultdict(lambda: [0, time()])
last_alert_time = {}

def detect_anomaly(ip):
    count, first_time = ip_packet_counts[ip]
    now = time()

    if now - first_time < 5:
        ip_packet_counts[ip][0] += 1
    else:
        ip_packet_counts[ip] = [1, now]

    if now - last_alert_time.get(ip, 0) < 15:
        return

    if ip_packet_counts[ip][0] > 50:
        alert = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "ip": ip,
            "message": "🚨 DoS Attack Detected (burst traffic)"
        }
        anomaly_alerts.append(alert)
        _send_ws_packet(alert)
        print(f"[!] ALERT: {alert['message']} from {ip}")
        last_alert_time[ip] = now

# === Safe WebSocket Push ===
def _send_ws_packet(data):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(push_packet_to_clients(data))
        else:
            asyncio.run(push_packet_to_clients(data))
    except Exception as e:
        print(f"[WebSocket ERROR] {e}")

# === Log Packet for AI Training ===
def log_packet_for_training(packet):
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/normal_traffic.csv", "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([packet["src"], packet["dst"], packet["proto"], packet["length"]])
    except Exception as e:
        print(f"[Log Error] Could not write packet to CSV: {e}")

# === Main Packet Processor ===
def process_packet(packet):
    if IP not in packet:
        return

    ip_layer = packet[IP]
    proto = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(ip_layer.proto, str(ip_layer.proto))
    src = ip_layer.src
    dst = ip_layer.dst
    length = len(packet)

    is_incoming = dst in local_ips
    is_outgoing = src in local_ips

    app_proto = None
    if packet.haslayer(DNS): app_proto = "DNS"
    elif packet.haslayer(HTTPRequest): app_proto = "HTTP"
    elif packet.haslayer(ICMP): app_proto = "ICMP"

    country_src, code_src = get_country_info(src)
    country_dst, code_dst = get_country_info(dst)

    data = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "hostname_src": get_hostname(src),
        "hostname_dst": get_hostname(dst),
        "proto": proto,
        "sport": getattr(packet, 'sport', None),
        "dport": getattr(packet, 'dport', None),
        "length": length,
        "app_proto": app_proto,
        "country_src": country_src,
        "country_dst": country_dst,
        "country_code_src": code_src,
        "country_code_dst": code_dst,
        "is_incoming": is_incoming,
        "is_outgoing": is_outgoing,
    }

    print(f"[PACKET] {src} → {dst} | {proto} | {length}B | {country_src} → {country_dst}")

    # === IP Reputation Check
    if src not in trusted_ips:
        rep = check_ip_reputation(src)
        if rep["is_malicious"]:
            data["alert_message"] = f"⚠️ Malicious IP (Fraud Score: {rep['fraud_score']})"
            if time() - last_alert_time.get(src, 0) > 15:
                anomaly_alerts.append({
                    "timestamp": data["timestamp"],
                    "ip": src,
                    "message": data["alert_message"]
                })
                _send_ws_packet(data)
                print(f"[!] MALICIOUS: {src} | Score: {rep['fraud_score']}")
                last_alert_time[src] = time()

    # === Rule Check
    for alert in check_custom_rules(data):
        if time() - last_alert_time.get(alert['ip'], 0) > 10:
            anomaly_alerts.append(alert)
            _send_ws_packet(alert)
            print("[!] RULE ALERT:", alert)
            last_alert_time[alert['ip']] = time()

    # === DoS Detection
    detect_anomaly(src)

    # === AI Model Detection
    if ai_model and src not in trusted_ips:
        proto_code = {"TCP": 0, "UDP": 1, "ICMP": 2}.get(proto, -1)
        try:
            prediction = ai_model.predict([[proto_code, length]])
            if prediction[0] == -1:
                data["alert_message"] = "⚠️ AI: Anomalous Packet Detected"
                anomaly_alerts.append({
                    "timestamp": data["timestamp"],
                    "ip": src,
                    "message": data["alert_message"]
                })
                _send_ws_packet(data)
                print(f"[🤖] AI ANOMALY: {src} | Len={length}")
        except Exception as e:
            print(f"[AI ERROR] {e}")

    # === Save and Stream
    packet_data.append(data)
    if len(packet_data) > 1000:
        packet_data.pop(0)

    live_packet_queue.append(data)
    if len(live_packet_queue) > 100:
        live_packet_queue.pop(0)

    if "alert_message" not in data:
        log_packet_for_training(data)

# === Start Sniffer ===
def start_sniffing():
    iface = get_best_interface()
    print(f"[*] Starting sniffing on interface: {iface}")
    try:
        sniff(iface=iface, prn=process_packet, filter="ip", store=False)
    except Exception as e:
        print(f"[❌] Sniffing failed on {iface}: {e}")


# simulate_traffic.py
import time
import random
from datetime import datetime
import asyncio

from app.websocket import push_packet_to_clients
from app.store import packet_data, live_packet_queue, anomaly_alerts

fake_ips = [
    "185.234.219.66", "203.0.113.10", "194.87.237.1", "198.51.100.23",
    "8.8.8.8", "142.250.77.14", "1.1.1.1"
]
countries = [("RU", "Russia"), ("IN", "India"), ("US", "USA"), ("CN", "China"), ("DE", "Germany")]

def generate_packet():
    src = random.choice(fake_ips)
    dst = "192.168.1.100"
    proto = random.choice(["TCP", "UDP", "ICMP"])
    length = random.randint(60, 1500)
    timestamp = datetime.now().strftime("%H:%M:%S")
    country_code_src, country_src = random.choice(countries)
    country_code_dst, country_dst = ("IN", "India")

    is_incoming = random.choice([True, False])  # ✅ This fixes it

    packet = {
        "timestamp": timestamp,
        "src": src,
        "dst": dst,
        "proto": proto,
        "sport": random.randint(1000, 9999),
        "dport": random.randint(20, 443),
        "length": length,
        "is_incoming": is_incoming,
        "country_src": country_src,
        "country_dst": country_dst,
        "country_code_src": country_code_src,
        "country_code_dst": country_code_dst,
        "app_proto": "HTTP" if proto == "TCP" else "DNS"
    }

    if random.random() < 0.3:
        packet["alert_message"] = "⚠️ Simulated Malicious Packet"
        anomaly_alerts.append({
            "timestamp": timestamp,
            "ip": src,
            "message": "Anomaly detected in simulated traffic"
        })

    live_packet_queue.append(packet)
    packet_data.append(packet)
    return packet


def start_simulation():
    print("🚀 Simulated traffic generator started.")

    async def run_loop():
        while True:
            packet = generate_packet()
            await push_packet_to_clients(packet)
            await asyncio.sleep(2)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_loop())

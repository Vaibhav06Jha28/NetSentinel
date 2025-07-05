# app/store.py

packet_data = []  # Stores all packets for dashboard display
anomaly_alerts = []  # Stores alerts for anomalies or IDS triggers
live_packet_queue = []  # Stores latest packets for WebSocket live updates

# Dashboard filters
filters = {
    "external_only": False,
    "tcp_only": False,
}


# ✅ Helper to check if IP is external (not private/internal)
def is_external(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("192.168."):
        return False
    # 172.16.0.0 – 172.31.255.255 range
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return False
        except (IndexError, ValueError):
            return False
    return True

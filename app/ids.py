from datetime import datetime

# Sample rules list for dynamic rules (from UI)
rules = []

def add_rule(keyword, message):
    rules.append({"field": "src", "operator": "==", "value": keyword, "message": message})

def delete_rule(keyword):
    global rules
    rules = [r for r in rules if r["value"] != keyword]

def check_custom_rules(data):
    alerts = []

    # Smart internal IP anomaly rule
    src = data.get("src", "")
    dst = data.get("dst", "")
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Only flag if EXTERNAL IP is trying to contact internal network
    if not src.startswith(("192.168.", "10.", "172.")) and dst.startswith(("192.168.", "10.", "172.")):
        alerts.append({
            "timestamp": timestamp,
            "ip": src,
            "message": "Unexpected external inbound traffic"
        })

    # Evaluate dynamic rules
    for rule in rules:
        field = rule["field"]
        operator = rule["operator"]
        value = rule["value"]

        if field not in data:
            continue

        try:
            packet_value = data[field]
            if isinstance(packet_value, int):
                value = int(value)

            condition = (
                (operator == "==" and packet_value == value) or
                (operator == "!=" and packet_value != value) or
                (operator == ">" and packet_value > value) or
                (operator == "<" and packet_value < value)
            )

            if condition:
                alerts.append({
                    "timestamp": timestamp,
                    "ip": data.get("src", "unknown"),
                    "message": rule["message"]
                })
        except Exception as e:
            print("[Rule Error]", e)

    return alerts

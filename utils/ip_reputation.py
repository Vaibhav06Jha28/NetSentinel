import requests
import ipaddress
import os

IPQS_API_KEY = "xsF9ymwGlNdEtpLXz9YTH5w9VFKb9jwv"  # Replace with your actual key
ip_cache = {}

TRUSTED_IP_FILE = "trusted_ips.txt"


def is_ip_private_or_trusted(ip: str) -> bool:
    try:
        # Skip private IP ranges
        if ipaddress.ip_address(ip).is_private:
            return True

        # Load trusted IPs from file
        if os.path.exists(TRUSTED_IP_FILE):
            with open(TRUSTED_IP_FILE, "r") as f:
                trusted_ips = {line.strip() for line in f if line.strip()}
            return ip in trusted_ips
    except Exception as e:
        print(f"[IP Check Error] {ip}: {e}")
    return False


def check_ip_reputation(ip: str) -> dict:
    if is_ip_private_or_trusted(ip):
        return {
            "fraud_score": 0,
            "is_proxy": False,
            "is_tor": False,
            "is_vpn": False,
            "is_mobile": False,
            "is_malicious": False
        }

    if ip in ip_cache:
        return ip_cache[ip]

    try:
        url = (
            f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
            f"?strictness=1&allow_public_access_points=true"
        )
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        result = {
            "fraud_score": data.get("fraud_score", 0),
            "is_proxy": data.get("proxy", False),
            "is_tor": data.get("tor", False),
            "is_vpn": data.get("vpn", False),
            "is_mobile": data.get("mobile", False),
            "is_malicious": data.get("fraud_score", 0) >= 75
        }

        ip_cache[ip] = result
        return result

    except Exception as e:
        print(f"[IPQS ERROR] {ip}: {e}")
        return {
            "fraud_score": 0,
            "is_proxy": False,
            "is_tor": False,
            "is_vpn": False,
            "is_mobile": False,
            "is_malicious": False
        }

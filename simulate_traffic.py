# simulate_traffic.py
import requests

urls = [
    "https://www.google.com",
    "https://www.cloudflare.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org"
]

for url in urls:
    try:
        response = requests.get(url)
        print(f"Hit {url}: {response.status_code}")
    except Exception as e:
        print(f"Error hitting {url}: {e}")

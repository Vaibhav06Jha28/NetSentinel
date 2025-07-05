# app/geoip.py
import geoip2.database
import ipaddress

reader = geoip2.database.Reader("data/GeoLite2-City.mmdb")

def get_country_info(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return "Private IP", "xx"
        if ip_obj.is_loopback:
            return "Loopback", "xx"
        if ip_obj.is_reserved:
            return "Reserved", "xx"

        response = reader.city(ip)  # ✅ use city
        country_name = response.country.name or "Unknown"
        country_code = response.country.iso_code.lower() if response.country.iso_code else "xx"
        return country_name, country_code

    except Exception as e:
        print(f"[GeoIP ERROR] {ip}: {e}")
        return "Unknown", "xx"

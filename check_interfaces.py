# check_interfaces.py
from scapy.all import get_if_list

interfaces = get_if_list()
print("Available interfaces:")
for iface in interfaces:
    print("-", iface)
from scapy.arch.windows import get_windows_if_list

interfaces = get_windows_if_list()
for iface in interfaces:
    print(f"Name: {iface['name']}")
    print(f"Description: {iface['description']}")
    print(f"GUID: {iface['guid']}")
    print(f"IP(s): {iface['ips']}")
    print("-----")

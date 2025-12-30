import sys
import requests

BASE_URL = "http://127.0.0.1:8000"


def fetch_scan():
    r = requests.get(f"{BASE_URL}/network/scan")
    return r.json()




def scan_network():
    data = fetch_scan()

    print("\nSmartLAN Scan Results")
    print("--------------------")
    print(f"Local IP: {data.get('local_ip')}\n")

    if "devices" in data:
        for d in data["devices"]:
            print(f"{d['ip']:15}  {d['role']}")
        count = data.get("count", len(data["devices"]))
    else:
        print("No devices found")
        count = 0

    print(f"\nTotal devices: {count}\n")




def render_topology():
    data = fetch_scan()

    devices = data.get("devices", [])
    local_ip = data.get("local_ip")

    router = None
    nodes = []

    for d in devices:
        if d.get("role") == "ROUTER":
            router = d
        else:
            nodes.append(d)

    print("\nSmartLAN – Network Topology (Logical)\n")

    # Router
    if router:
        print("              ┌───────────────┐")
        print("              │   ROUTER       │")
        print(f"              │ {router['ip']:<13}│")
        print("              └───────┬───────┘")
    else:
        print("              [ Router not detected ]")
        return

    if not nodes:
        print("                      │")
        print("                 (no devices)")
        return

    # Connection bar
    print("                      │")
    print("   " + "───────────────┼" * len(nodes))

    # Top of boxes
    for _ in nodes:
        print("      ┌─────────┐", end="  ")
    print()

    # Device labels
    for d in nodes:
        role = d.get("role", "UNKNOWN")
        ip = d.get("ip")

        if role == "SELF":
            label = "THIS DEVICE"
        else:
            label = "UNKNOWN"

        print(f"      │{label:^9}│", end="  ")
    print()

    # IP lines
    for d in nodes:
        ip = d.get("ip")
        print(f"      │{ip:^9}│", end="  ")
    print()

    # Bottom of boxes
    for _ in nodes:
        print("      └─────────┘", end="  ")
    print()

    print("\nLegend:")
    print(" ROUTER         → Network gateway")
    print(" THIS DEVICE    → Your laptop")
    print(" UNKNOWN        → Phone / other device")
    print()










def trust_device(ip):
    r = requests.post(f"{BASE_URL}/network/trust/{ip}")
    if r.status_code == 200:
        print(f"\n✔ Device {ip} marked as TRUSTED\n")
    else:
        print("\n✖ Failed to trust device\n")


def help_menu():
    print("""
SmartLAN CLI Usage:

  python3 smartlan.py scan
      Scan local network and list devices

  python3 smartlan.py topo
      Show logical network topology (terminal view)

  python3 smartlan.py trust <ip>
      Mark a device as trusted

  python3 smartlan.py help
      Show this help menu
""")


def main():
    if len(sys.argv) < 2:
        help_menu()
        return

    cmd = sys.argv[1]

    if cmd == "scan":
        scan_network()
    elif cmd == "topo":
        render_topology()
    elif cmd == "trust":
        if len(sys.argv) < 3:
            print("Usage: python3 smartlan.py trust <ip>")
            return
        trust_device(sys.argv[2])
    else:
        help_menu()


if __name__ == "__main__":
    main()

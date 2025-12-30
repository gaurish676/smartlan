from fastapi import FastAPI
import socket
import psutil
from scapy.all import ARP, Ether, srp

app = FastAPI(title="SmartLAN")

# ----------------------------
# Offline MAC vendor map
# ----------------------------
MAC_VENDOR_MAP = {
    "3C:22:FB": ("Samsung", "PHONE"),
    "F0:99:B6": ("Samsung", "PHONE"),
    "AC:37:43": ("Apple", "PHONE/LAPTOP"),
    "BC:54:36": ("Apple", "PHONE/LAPTOP"),
    "D8:BB:C1": ("Dell", "LAPTOP"),
    "F4:8C:50": ("HP", "LAPTOP"),
    "00:1A:2B": ("TP-Link", "ROUTER"),
    "00:18:E7": ("Cisco", "ROUTER"),
}


def identify_device(mac):
    if not mac:
        return ("Unknown", "UNKNOWN")

    prefix = mac.upper()[0:8]
    return MAC_VENDOR_MAP.get(prefix, ("Unknown", "UNKNOWN"))


def arp_scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for _, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


@app.get("/")
def root():
    return {
        "status": "SmartLAN backend running",
        "mode": "offline"
    }


@app.get("/network/scan")
def network_scan():
    local_ip = None

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                local_ip = addr.address
                break
        if local_ip:
            break

    if not local_ip:
        return {"error": "No LAN IP found"}

    subnet = local_ip + "/24"
    arp_devices = arp_scan(subnet)

    devices = []
    for d in arp_devices:
        if d["ip"] == local_ip:
            role = "SELF"
        elif d["ip"].endswith(".1"):
            role = "ROUTER"
        else:
            role = "UNKNOWN"

        vendor, dtype = identify_device(d["mac"])

        devices.append({
            "ip": d["ip"],
            "mac": d["mac"],
            "role": role,
            "vendor": vendor,
            "device_type": dtype
        })

    return {
        "local_ip": local_ip,
        "devices": devices,
        "count": len(devices),
        "method": "ARP scan"
    }

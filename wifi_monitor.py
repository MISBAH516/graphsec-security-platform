"""
GraphSec WiFi Monitor
=====================
Yeh script automatically aapke WiFi network ko monitor karta hai.
Har 30 second mein scan karta hai aur naya device mile to GraphSec mein log karta hai.

HOW TO RUN:
1. Pehle GraphSec server chala lo: uvicorn backend.main:app --host 0.0.0.0 --port 8000
2. Pehle login karo aur TOKEN copy karo
3. Neeche TOKEN mein apna token paste karo
4. Phir run karo: python wifi_monitor.py
"""

import subprocess
import requests
import time
import re
from datetime import datetime

# ── SETTINGS — YAHAN APNA TOKEN PASTE KARO ────────────────────
TOKEN = "APNA_LOGIN_TOKEN_YAHAN_PASTE_KARO"
API_URL = "http://127.0.0.1:8000"   # ya apna IP jaise http://192.168.100.11:8000
SCAN_INTERVAL = 30  # har kitne seconds baad scan kare
# ──────────────────────────────────────────────────────────────

HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

known_devices = set()
first_scan = True


def log_event(event_type: str, description: str, severity: str, source_ip: str):
    """GraphSec mein event log karo."""
    try:
        res = requests.post(f"{API_URL}/events/",
            headers=HEADERS,
            json={
                "event_type": event_type,
                "description": description,
                "severity": severity,
                "source_ip": source_ip
            },
            timeout=5
        )
        if res.status_code == 201:
            print(f"  ✅ Event logged: {event_type} — {source_ip}")
        else:
            print(f"  ⚠️  Event log failed: {res.status_code}")
    except Exception as e:
        print(f"  ❌ API Error: {e}")


def create_threat(title: str, description: str, severity: str):
    """GraphSec mein threat create karo."""
    try:
        res = requests.post(f"{API_URL}/threats/",
            headers=HEADERS,
            json={
                "title": title,
                "description": description,
                "severity": severity,
                "status": "open"
            },
            timeout=5
        )
        if res.status_code == 201:
            print(f"  🚨 THREAT CREATED: {title}")
        else:
            print(f"  ⚠️  Threat creation failed: {res.status_code}")
    except Exception as e:
        print(f"  ❌ API Error: {e}")


def scan_network():
    """ARP table se connected devices nikaalo."""
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        devices = {}
        for line in result.stdout.split('\n'):
            # IP address extract karo
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(0)
                # Only local network IPs
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                    devices[ip] = mac
        return devices
    except Exception as e:
        print(f"  ❌ Scan error: {e}")
        return {}


def check_suspicious_ips(devices: dict):
    """Check karo koi suspicious IP to nahi."""
    suspicious_ranges = ['10.0.0.', '172.16.']
    for ip in devices:
        for sus_range in suspicious_ranges:
            if ip.startswith(sus_range):
                create_threat(
                    title=f"Suspicious IP Range Detected: {ip}",
                    description=f"Device with IP {ip} (MAC: {devices[ip]}) found in suspicious IP range.",
                    severity="medium"
                )


def run_monitor():
    global known_devices, first_scan

    print("=" * 55)
    print("  🔐 GraphSec WiFi Monitor Started")
    print(f"  📡 Scanning every {SCAN_INTERVAL} seconds")
    print(f"  🌐 API: {API_URL}")
    print("=" * 55)

    # Check token
    try:
        res = requests.get(f"{API_URL}/users/me", headers=HEADERS, timeout=5)
        if res.status_code == 200:
            user = res.json()
            print(f"  ✅ Connected as: {user['username']} ({user['role']})")
        else:
            print("  ❌ Invalid token! Login karo aur TOKEN update karo.")
            return
    except Exception:
        print("  ❌ Cannot connect to GraphSec server! Pehle uvicorn chalaao.")
        return

    print("\n  🔍 Starting network scan...\n")

    while True:
        try:
            current_time = datetime.now().strftime("%H:%M:%S")
            print(f"[{current_time}] Scanning network...")

            current_devices = scan_network()
            print(f"  📱 Found {len(current_devices)} devices on network")

            for ip, mac in current_devices.items():
                if ip not in known_devices:
                    if first_scan:
                        # Pehli baar scan — sirf known mein add karo
                        print(f"  📌 Known device: {ip} ({mac})")
                        known_devices.add(ip)
                    else:
                        # Naya device mila!
                        print(f"\n  🆕 NEW DEVICE DETECTED: {ip} ({mac})")
                        log_event(
                            event_type="New Device Connected to WiFi",
                            description=f"Unknown device joined network. IP: {ip}, MAC: {mac}",
                            severity="medium",
                            source_ip=ip
                        )
                        # Check if suspicious
                        check_suspicious_ips({ip: mac})
                        known_devices.add(ip)

            # Check agar koi device disconnect hua
            if not first_scan:
                disconnected = known_devices - set(current_devices.keys())
                for ip in disconnected:
                    print(f"  👋 Device disconnected: {ip}")
                    log_event(
                        event_type="Device Disconnected from WiFi",
                        description=f"Device with IP {ip} left the network.",
                        severity="low",
                        source_ip=ip
                    )
                    known_devices.discard(ip)

            if first_scan:
                print(f"\n  ✅ Initial scan complete. Monitoring {len(known_devices)} devices.")
                print(f"  👀 Watching for new devices...\n")
                first_scan = False

            time.sleep(SCAN_INTERVAL)

        except KeyboardInterrupt:
            print("\n\n  🛑 Monitor stopped by user.")
            break
        except Exception as e:
            print(f"  ❌ Error: {e}")
            time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    if TOKEN == "APNA_LOGIN_TOKEN_YAHAN_PASTE_KARO":
        print("❌ ERROR: Pehle TOKEN set karo!")
        print("\nToken kaise milega:")
        print("1. http://127.0.0.1:8000/docs open karo")
        print("2. POST /auth/login mein login karo")
        print("3. Response mein access_token copy karo")
        print("4. Is file mein TOKEN = 'your_token' set karo")
    else:
        run_monitor()

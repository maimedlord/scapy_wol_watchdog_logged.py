#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP
import subprocess
import time
import os

# ---------------- CONFIGURATION ----------------

SERVER_IP = "192.168.10.2"            # The IP address of the target server
SERVER_MAC = "04:92:26:d8:ba:2e"      # The MAC address of the server for WOL
WOL_INTERVAL = 60                     # Seconds between allowed WOL sends
AWAKE_CHECK_INTERVAL = 300            # Seconds between pings to re-check if server is awake
AFTER_AWAKE_SLEEP = 30
INTERFACE = "wlan0"                   # Network interface to sniff
LOG_FILE = "/var/log/scapy_wol_watchdog.log"  # Persistent log file

# Monitored TCP/UDP ports to identify legitimate user activity
MONITORED_PORTS = {
    "TCP": [22, 80, 443, 445] + list(range(9100, 9201)) + list(range(9330, 9340)),
    "UDP": [9003]
}

# ---------------- STATE ----------------

last_wake_time = 0
last_awake_check_time = 0
server_awake = None

# ---------------- LOGGING FUNCTION ----------------

def log(msg):
    # Write a log entry to stdout and append to the log file.
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {msg}"
    print(entry, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to write to log: {e}", flush=True)

# ---------------- SERVER CHECK & WAKE ----------------

def is_server_awake():
    # Use ping to check if the server is currently awake and reachable.
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", SERVER_IP],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        log(f"[ERROR] Ping failed: {e}")
        return False

def wake_server():
    # Send the WOL magic packet to the server using wakeonlan.
    log(f"[WOL] Sending magic packet to {SERVER_MAC}")
    try:
        subprocess.run(["wakeonlan", "-i", "192.168.10.255", SERVER_MAC],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log(f"[ERROR] Failed to send WOL: {e}")

# ---------------- PACKET HANDLER ----------------

def handle_packet(pkt):
    # Process each sniffed packet and determine whether to trigger a wake event.
    global last_wake_time, last_awake_check_time, server_awake

    now = time.time()

    # Re-check server awake state only if needed
    if server_awake is None or now - last_awake_check_time > AWAKE_CHECK_INTERVAL:
        server_awake = is_server_awake()
        last_awake_check_time = now
        log(f"[STATUS] Server awake = {server_awake}")

    # Skip if already awake
    if server_awake:
        return

    if IP not in pkt or pkt[IP].dst != SERVER_IP:
        return  # Not destined for the server; ignore

    src_ip = pkt[IP].src

    # Handle TCP traffic
    if TCP in pkt:
        dport = pkt[TCP].dport
        syn_flag = pkt[TCP].flags & 0x02 != 0  # SYN
        ack_flag = pkt[TCP].flags & 0x10 != 0  # ACK

        # Port 22 (SSH) requires SYN-only (initial handshake)
        if dport == 22:
            if not syn_flag or ack_flag:
                return  # Not a new SSH connection attempt
            protocol = "TCP-SYN"
        elif dport in MONITORED_PORTS["TCP"]:
            protocol = "TCP"
        else:
            return  # Not a monitored TCP port

    # Handle UDP traffic (e.g., Roon discovery)
    elif UDP in pkt:
        dport = pkt[UDP].dport
        if dport not in MONITORED_PORTS["UDP"]:
            return  # Not a monitored UDP port
        protocol = "UDP"

    else:
        return  # Not TCP or UDP; ignore

    # Log the detected intent
    log(f"[DETECT] {protocol} packet from {src_ip} to {SERVER_IP}:{dport}")

    # Check cooldown timer before sending WOL
    if now - last_wake_time >= WOL_INTERVAL:
        wake_server()
        last_wake_time = now

        # sleep to give the server some time to boot up and not spam log
        log(f"[INFO] watchdog sleeping for {AFTER_AWAKE_SLEEP} seconds after sending wake to server")
        time.sleep(AFTER_AWAKE_SLEEP)

# ---------------- MAIN ----------------

def main():
    # Main entry point: initialize log and start sniffing.
    log("🟢 Scapy WOL Watchdog (SYN+Port-aware) started")
    log(f"🔎 Monitoring interface '{INTERFACE}' for traffic to {SERVER_IP}")
    try:
        sniff(prn=handle_packet, store=0, iface=INTERFACE)
    except Exception as e:
        log(f"[FATAL] Scapy sniffing failed: {e}")

if __name__ == "__main__":
    main()
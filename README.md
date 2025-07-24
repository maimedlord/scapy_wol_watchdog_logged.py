
# 🛡️ Scapy WOL Watchdog

A lightweight, headless Python script for Raspberry Pi 5 (or similar devices) that passively monitors network traffic using `scapy` and sends a Wake-on-LAN (WOL) packet to wake a sleeping server based on specific client activity.

---

## 🔍 Overview

This script watches real-time network traffic for TCP/UDP packets on specified ports (e.g. SMB, SSH, HTTP, Roon discovery, etc.). When traffic is detected and the server is asleep, it sends a WOL packet to wake it up.

Ideal for setups where your main server sleeps to conserve power and is only needed when a user initiates contact.

---

## ⚙️ Features

- 🔄 Passive network monitoring with `scapy`
- 🎯 Port-specific filtering (TCP & UDP)
- 🧠 Smart logic: triggers only on new connection attempts (e.g. TCP SYN)
- 💡 Sleep-aware: checks if the server is already awake
- ⏱️ Cooldown between wake attempts
- 📝 Persistent logging
- 🧵 Runs as a simple long-lived script or background process

---

## 📦 Requirements

- Python 3.7+
- [`scapy`](https://scapy.readthedocs.io/)
- `wakeonlan` (CLI utility)

Install:
```bash
sudo apt install wakeonlan
pip install scapy
```

---

## 🛠️ Configuration

Edit the top of the script to set:

```python
SERVER_IP = "xxx.xxx.xxx.xxx"
SERVER_MAC = "xx:xx:xx:xx:xx:xx"
INTERFACE = "wlan0"
MONITORED_PORTS = {
    "TCP": [22, 80, 443, 445],
    "UDP": [9003]
}
```

---

## 🚀 Usage

Run the script with:
```bash
sudo python3 scapy_watchdog_logged.py
```

> Note: `sudo` is required for raw packet sniffing.

To run at boot, consider using `systemd` or a background service manager like `pm2`.

---

## 🧠 Example Use Cases

- Wake a NAS or media server when accessing SMB shares
- Wake an AI server when triggering a web API
- Wake on SSH or Roon client connection attempts

---

## 📄 License

MIT — feel free to build, remix, and deploy.

---

## 🙌 Credits

Created by Alex Haas, designed for ultra-efficient local automation and smart energy-saving servers.

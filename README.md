# 🛡️ TrafficSpy
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5.0-blue?style=for-the-badge)

[![GitHub Stars](https://img.shields.io/github/stars/6-ft/network-traffic-analyzer?style=social)](https://github.com/6-ft/network-traffic-analyzer/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/6-ft/network-traffic-analyzer?style=social)](https://github.com/6-ft/network-traffic-analyzer/issues)

A professional Network Traffic Analysis tool designed for Deep Packet Inspection (DPI). This tool automates the process of reading `.pcap` files to identify network anomalies, top-talking devices, and protocol distributions.

---

## 🛠️ Requirements & Tools

To run this analyzer effectively, the following tools and environment are required:

### 1. Python Environment
* **Python 3.8+**: Ensure you have the latest stable version of Python.
* **Scapy Library**: The core engine used for packet parsing and dissection.

### 2. Network Drivers (Crucial)

* **Windows Users**: You must install **Npcap** (in WinPcap compatibility mode) to allow Python to interface with the network stack. Download it from [npcap.com](https://npcap.com/).
* **Linux/macOS Users**: Ensure **libpcap** is installed (usually pre-installed or available via `apt-get install libpcap-dev`).

### 3. Traffic Viewing (Optional but Recommended)
* **Wireshark**: While this script performs the analysis, Wireshark is recommended for visually verifying the contents of your `demo.pcap` files.

---

## 🚀 Technical Stack
* **Language:** Python 3
* **Library:** Scapy (Packet Manipulation)
* **Data Handling:** Collections (Counter for statistical analysis)
* **Format:** PCAP (Packet Capture)

---

## 💻 Quick Start

### 1. Installation
```bash
git clone [https://github.com/6-ft/network-traffic-analyzer.git](https://github.com/6-ft/network-traffic-analyzer.git)
cd network-traffic-analyzer
pip install -r requirements.txt 
python analyzer.py
```
## 👨‍💻 Author
Pulkit

GitHub: @6-ft

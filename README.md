# 🔍 CodeAlpha — Basic Network Sniffer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Scapy-2.5%2B-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/CodeAlpha-Internship-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge" />
</p>

> **Task 1** of the **CodeAlpha Cybersecurity Internship** — A professional, multi-feature network packet sniffer built with Python and Scapy. Captures, filters, displays, and analyzes live network traffic in real time.

---

## 📸 Features

| Feature | Description |
|---|---|
| 🎨 **Color-coded output** | Each protocol (TCP, UDP, ICMP, DNS, HTTP, ARP) has a distinct color |
| 🔎 **Protocol filtering** | Show only the protocols you care about |
| 🌐 **IP & port filtering** | Focus on a specific host or port |
| 📦 **Payload preview** | Optionally display raw TCP payload bytes |
| 📊 **Live statistics** | Rolling stats every 50 packets |
| 💾 **JSON export** | Save all captured packets to a structured JSON log |
| 📈 **Offline analyzer** | Run `analyzer.py` on a saved log for detailed reports |

---

## 🛡️ Protocols Detected

- **TCP** — flags (SYN, ACK, FIN, RST, PSH, URG), ports
- **UDP** — ports, datagram length
- **ICMP** — Echo Request/Reply, Destination Unreachable
- **DNS** — queried domain names
- **HTTP** — method, host, path (via Scapy HTTP layer)
- **ARP** — Request/Reply, MAC addresses

---

## 📁 Project Structure

```
CodeAlpha_BasicNetworkSniffer/
├── sniffer.py          # 🚀 Main sniffer — live packet capture & display
├── analyzer.py         # 📊 Offline analyzer — reads JSON logs, generates report
├── requirements.txt    # 📦 Python dependencies
└── README.md           # 📖 This file
```

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

> **Note:** On Linux, Scapy requires `libpcap`. Install it with:
> ```bash
> sudo apt install libpcap-dev
> ```

---

## 🚀 Usage

### Basic capture (all protocols)
```bash
sudo python sniffer.py
```

### Capture on a specific interface
```bash
sudo python sniffer.py -i eth0
```

### Capture exactly 200 packets
```bash
sudo python sniffer.py -c 200
```

### Filter by protocol
```bash
sudo python sniffer.py --filter-proto TCP DNS
sudo python sniffer.py --filter-proto HTTP
```

### Filter by IP address
```bash
sudo python sniffer.py --filter-ip 192.168.1.100
```

### Filter by port
```bash
sudo python sniffer.py --filter-port 443
```

### Show TCP payload preview
```bash
sudo python sniffer.py --payload
```

### Enable live stats every 50 packets
```bash
sudo python sniffer.py --live-stats
```

### Save captured packets to JSON
```bash
sudo python sniffer.py -o capture.json
```

### Combine options
```bash
sudo python sniffer.py -i wlan0 -c 500 --filter-proto TCP HTTP DNS --payload --live-stats -o session.json
```

---

## 📊 Offline Analysis

After capturing to a JSON file, run the analyzer for a detailed report:

```bash
python analyzer.py capture.json
```

**The analyzer shows:**
- Protocol distribution with visual bar charts
- Top 10 source & destination IP addresses
- DNS domains queried
- HTTP requests captured
- Packet-per-second timeline

---

## 🖥️ Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║           CodeAlpha — Basic Network Sniffer | Task 1               ║
╚══════════════════════════════════════════════════════════════════════╝

[*] Sniffing on interface: eth0 | Count: ∞

Timestamp       #      Proto  Source               Destination          Info
──────────────────────────────────────────────────────────────────────
10:22:43.512  #1      [  TCP]  192.168.1.5          142.250.186.46       Port 54321 → 443  [SYN]
10:22:43.515  #2      [  DNS]  192.168.1.5          8.8.8.8              Query: www.google.com
10:22:43.520  #3      [ HTTP]  192.168.1.5          93.184.216.34        GET example.com/index.html
10:22:43.530  #4      [ ICMP]  192.168.1.1          192.168.1.5          Echo Request
10:22:43.531  #5      [  ARP]  192.168.1.1          192.168.1.5          Request  aa:bb:cc:dd:ee:ff → ...
```

---

## 🔐 Ethical & Legal Notice

> This tool is developed **strictly for educational purposes** as part of the CodeAlpha Internship. Only use it on networks you own or have explicit written permission to monitor. Unauthorized packet capture may violate local laws. The author accepts no responsibility for misuse.

---

## 🧑‍💻 Author

**Majd El-Masri**  
CodeAlpha Cybersecurity Intern — 2025  
📧 majdmasri06@gmail.com  

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<p align="center">Made with ❤️ for the <strong>CodeAlpha Cybersecurity Internship</strong></p>

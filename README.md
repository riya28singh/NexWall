# NexWall
# 🔥 NexWall – Python-Based Inbound Firewall for Linux

**NexWall** is a user-friendly, Python-based personal firewall designed to block **incoming (inbound)** traffic via a graphical interface. Built using `tkinter`, `iptables`, and `Scapy`, it lets users apply IP, port, or protocol-based filtering — ideal for security learners and Linux users wanting GUI control over their system's firewall.

---

## 📌 Project Highlights

- 🧱 **Inbound traffic blocking only** – protect your system from external access
- 👁️ **Live packet sniffing** using Scapy
- 🖱️ **Tkinter GUI** for adding/removing firewall rules easily
- 📜 **Event logs** for every blocked action (saved in `gui_firewall.log`)
- 💾 **Persistent rule saving** using `gui_rules.json`
- 🔐 Uses **iptables** to apply kernel-level filtering for high reliability

---

## ⚙️ Technologies Used

- **Python 3**
- **Tkinter** (GUI framework)
- **Scapy** (packet sniffing)
- **iptables** (Linux packet filtering)

---

## ⚠️ Root Access Required

To apply `iptables` rules and capture packets, this app must be run with **root privileges**.

```bash
sudo python3 gui_firewall.py


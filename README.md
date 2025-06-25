
# 🔥 NexWall – GUI-Based Personal Firewall for Linux

**NexWall** is a user-friendly personal firewall with a graphical interface built using Python and Tkinter. It allows you to block incoming traffic by **IP address**, **port**, or **protocol**, and logs all firewall activity. Designed for **Linux systems** with `iptables`, it's ideal for personal and educational network security monitoring.
This project was built during my internship at Elevate Labs as my final project. It was a great opportunity to apply what I’d learned and contribute to something real. I handled everything from design to implementation, aiming to build something useful and well-crafted.


---

## 📌 Project Highlights

- 🔐 **Block incoming traffic** by IP, port, or protocol via GUI
- 🧱 **Uses iptables** for real firewall rule enforcement
- 🧠 **Built-in logging** with timestamps of blocked actions
- 💾 **Persistent rule management** via `gui_rules.json`
- 📋 **Log viewer** to inspect blocked connections in real-time
- ⚙️ **Start/stop firewall sniffing** directly from the interface
- 🪟 **Modern and clean Tkinter GUI**

---

## ⚙️ Technologies Used

- **Python 3**
- **Tkinter** (GUI)
- **Scapy** (packet sniffing)
- **iptables** (Linux firewall)
- **Linux OS** (tested on Kali)

---

## ⚠️ Root Access Required

NexWall modifies `iptables` and captures packets, which requires root privileges.

Run it using:

```bash
sudo python3 gui_firewall.py
```

> Without `sudo`, packet sniffing and firewall modifications won’t function correctly.

---

## 📁 Auto-Generated Files

The following files are automatically created when you run NexWall:

| File Name          | Description                                              |
|--------------------|----------------------------------------------------------|
| `gui_rules.json`   | Stores all blocked rules (IP, Port, Protocol)            |
| `gui_firewall.log` | Log file with time-stamped entries of blocked packets    |

---

## 📦 Required Python Libraries

```
scapy
```

> Other modules used like `tkinter`, `threading`, `json`, etc., come with Python 3.

---

## 📄 requirements.txt

Below is the content for your `requirements.txt` file:

```
scapy
```

Install the requirements with:

```bash
pip install -r requirements.txt
```

---

## ▶️ How to Use

### 1. Clone the Repository

```bash
git clone git@github.com:riya28singh/NexWall.git
cd NexWall
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Application (with sudo)

```bash
sudo python3 gui_firewall.py
```

---

## 🖥 GUI Options Overview

The GUI provides intuitive buttons to:

- **Block IP** – Drop incoming traffic from a specific IP
- **Block Protocol** – Drop packets by protocol number (e.g., `1` for ICMP)
- **Block Port** – Block a specific port for TCP or UDP
- **Remove Rule** – Remove a selected rule and update iptables
- **Start Firewall** – Begin real-time packet sniffing with Scapy
- **Stop Firewall** – Stop sniffing
- **View Logs** – Open a scrollable window showing the block log
- **Exit** – Close the application

---

## 💡 Example Use Case

1. Launch NexWall as root:
   ```bash
   sudo python3 gui_firewall.py
   ```

2. In the GUI:
   - Enter `192.168.1.10` and click **Block IP**.
   - Select `tcp` and port `80`, then click **Block Port**.
   - Start the firewall to begin sniffing traffic.
   - View logs to inspect what was blocked and when.

---

## 👩‍💻 Author

**Riya Singh**  
Intership Project – Python GUI Network Security Tool

---

## ⚠️ Disclaimer

This tool is for **educational and ethical use only**. Do not run it on networks you do not own or have explicit permission to monitor or modify.

---

import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import threading
import json
import scapy.all as scapy
import os
import subprocess
import logging

RULES_FILE = "gui_rules.json"
LOG_FILE = "gui_firewall.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')


def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    return []


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)


def log_packet(packet, reason):
    logging.info(f"{reason}: {packet.summary()}")


def packet_filter(packet, rules):
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        for rule in rules:
            if rule.get("ip") in (src_ip, dst_ip):
                log_packet(packet, "Blocked IP rule")
                return False
            if rule.get("proto") == str(proto):
                log_packet(packet, "Blocked protocol rule")
                return False
    return True


# IPTABLES Management
def apply_iptables_block(ip):
    try:
        subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
        logging.info(f"iptables: Blocked IP {ip}")
    except subprocess.CalledProcessError as e:
        logging.error(f"iptables error: {e}")


def apply_port_block(port, protocol):
    try:
        subprocess.run(f"iptables -A INPUT -p {protocol} --dport {port} -j DROP", shell=True, check=True)
        logging.info(f"iptables: Blocked {protocol} port {port}")
    except subprocess.CalledProcessError as e:
        logging.error(f"iptables port error: {e}")


def remove_iptables_rule(ip=None, port=None, protocol=None):
    try:
        if ip:
            subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True)
        elif port and protocol:
            subprocess.run(f"iptables -D INPUT -p {protocol} --dport {port} -j DROP", shell=True)
        logging.info(f"iptables: Rule removed")
    except subprocess.CalledProcessError as e:
        logging.error(f"iptables remove error: {e}")


class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Personal Firewall with iptables")
        self.rules = load_rules()
        self.sniffing = False

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        self.status_label = ttk.Label(frame, text="Status: Idle")
        self.status_label.pack(pady=5)

        self.rule_listbox = tk.Listbox(frame, height=10, width=60)
        self.rule_listbox.pack(pady=5)

        self.update_rule_list()

        entry_frame = ttk.Frame(frame)
        entry_frame.pack(pady=5)

        # IP Block
        self.ip_entry = ttk.Entry(entry_frame, width=15)
        self.ip_entry.grid(row=0, column=0)
        ttk.Button(entry_frame, text="Block IP", command=self.block_ip).grid(row=0, column=1)

        # Protocol Block
        self.proto_entry = ttk.Entry(entry_frame, width=10)
        self.proto_entry.grid(row=1, column=0)
        ttk.Button(entry_frame, text="Block Protocol", command=self.block_proto).grid(row=1, column=1)

        # Port Block
        self.port_entry = ttk.Entry(entry_frame, width=10)
        self.port_entry.grid(row=2, column=0)
        self.proto_select = ttk.Combobox(entry_frame, values=["tcp", "udp"], width=7)
        self.proto_select.grid(row=2, column=1)
        ttk.Button(entry_frame, text="Block Port", command=self.block_port).grid(row=2, column=2)

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Start Firewall", command=self.start_firewall).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Stop Firewall", command=self.stop_firewall).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_selected_rule).grid(row=0, column=2, padx=5)
        ttk.Button(btn_frame, text="View Logs", command=self.view_logs).grid(row=0, column=3, padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.root.quit).grid(row=0, column=4, padx=5)

    def update_rule_list(self):
        self.rule_listbox.delete(0, tk.END)
        for rule in self.rules:
            if "ip" in rule:
                display = f"Block IP: {rule['ip']}"
            elif "proto" in rule and "port" in rule:
                display = f"Block Port {rule['port']}/{rule['proto']}"
            elif "proto" in rule:
                display = f"Block Protocol {rule['proto']}"
            else:
                display = str(rule)
            self.rule_listbox.insert(tk.END, display)

    def block_ip(self):
        ip = self.ip_entry.get()
        if ip:
            self.rules.append({"ip": ip})
            save_rules(self.rules)
            apply_iptables_block(ip)
            self.update_rule_list()
            self.ip_entry.delete(0, tk.END)

    def block_proto(self):
        proto = self.proto_entry.get()
        if proto and proto.isdigit():
            self.rules.append({"proto": proto})
            save_rules(self.rules)
            self.update_rule_list()
            self.proto_entry.delete(0, tk.END)

    def block_port(self):
        port = self.port_entry.get()
        proto = self.proto_select.get()
        if port.isdigit() and proto:
            self.rules.append({"port": port, "proto": proto})
            save_rules(self.rules)
            apply_port_block(port, proto)
            self.update_rule_list()
            self.port_entry.delete(0, tk.END)
            self.proto_select.set("")

    def remove_selected_rule(self):
        selection = self.rule_listbox.curselection()
        if selection:
            index = selection[0]
            rule = self.rules.pop(index)
            save_rules(self.rules)

            if "ip" in rule:
                remove_iptables_rule(ip=rule["ip"])
            elif "port" in rule and "proto" in rule:
                remove_iptables_rule(port=rule["port"], protocol=rule["proto"])

            self.update_rule_list()

    def view_logs(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("Logs", "No logs available.")
            return

        log_win = tk.Toplevel(self.root)
        log_win.title("Firewall Logs")
        log_text = scrolledtext.ScrolledText(log_win, width=80, height=25)
        log_text.pack(padx=10, pady=10)

        with open(LOG_FILE, "r") as f:
            log_text.insert(tk.END, f.read())
        log_text.config(state=tk.DISABLED)

    def start_firewall(self):
        if not self.sniffing:
            self.sniffing = True
            self.status_label.config(text="Status: Running")
            threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_firewall(self):
        self.sniffing = False
        self.status_label.config(text="Status: Stopped")

    def sniff_packets(self):
        def process(packet):
            if self.sniffing and not packet_filter(packet, self.rules):
                return
        scapy.sniff(prn=process, store=False)


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

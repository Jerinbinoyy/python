import os
import sys
import atexit
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *
import threading
from datetime import datetime

# Define known safe Wi-Fi networks
known_access_points = {
    "HomeWiFi": {"BSSID": "AA:BB:CC:DD:EE:FF", "Channel": 6},
    "OfficeWiFi": {"BSSID": "11:22:33:44:55:66", "Channel": 11},
}

# Global variables
rogue_aps = {}
evil_twin_suspects = {}
scanning = False
base_interface = "wlp3s0"  # Change this to your Wi-Fi card name
monitor_interface = None   # Will be detected dynamically


# Check if monitor mode is supported
def check_monitor_mode_support():
    output = os.popen("iw list | grep -A 10 'Supported interface modes'").read()
    return "monitor" in output


# Enable Monitor Mode Automatically
def enable_monitor_mode():
    global monitor_interface
    print("[INFO] Enabling monitor mode...")

    # Stop NetworkManager and wpa_supplicant to prevent conflicts
    os.system("sudo systemctl stop NetworkManager")
    os.system("sudo systemctl stop wpa_supplicant")
    os.system("sudo airmon-ng check kill")
    os.system(f"sudo airmon-ng start {base_interface}")

    # Detect monitor mode interface dynamically
    output = os.popen("iwconfig").read()
    monitor_ifaces = [line.split()[0] for line in output.split("\n") if "Mode:Monitor" in line]

    if monitor_ifaces:
        monitor_interface = monitor_ifaces[0]
        print(f"[INFO] Monitor mode enabled on {monitor_interface}")
    else:
        print("[ERROR] Monitor mode not enabled. Exiting...")
        sys.exit(1)


# Restore Normal Wi-Fi Mode
def disable_monitor_mode():
    global monitor_interface
    if monitor_interface:
        os.system(f"sudo airmon-ng stop {monitor_interface}")
        os.system("sudo systemctl start NetworkManager")
        os.system("sudo systemctl start wpa_supplicant")
        print("[INFO] Network restored.")


# Restore normal mode when script exits
atexit.register(disable_monitor_mode)


# GUI setup
class RogueAPDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue AP Detector")

        self.start_btn = tk.Button(root, text="Start Scanning",
                                   command=self.start_scan, bg="green", fg="white")
        self.start_btn.pack(pady=5)

        self.stop_btn = tk.Button(root, text="Stop Scanning",
                                  command=self.stop_scan, bg="red", fg="white", state=tk.DISABLED)
        self.stop_btn.pack(pady=5)

        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.log_area.pack(pady=10)
        self.log_area.insert(tk.END, "Ready to scan for rogue access points...\n")

    def log(self, message, color="black"):
        self.log_area.insert(tk.END, message + "\n", color)
        self.log_area.tag_config(color, foreground=color)
        self.log_area.yview(tk.END)

    def start_scan(self):
        global scanning
        scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log("[INFO] Starting scan for rogue APs...", "blue")

        threading.Thread(target=self.sniff_rogue_aps, daemon=True).start()

    def stop_scan(self):
        global scanning
        scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("[INFO] Stopped scanning.", "blue")

    def sniff_rogue_aps(self):
        enable_monitor_mode()
        if monitor_interface:
            sniff(iface=monitor_interface, prn=packet_handler,
                  store=0, filter="type mgt",
                  stop_filter=lambda x: not scanning, promisc=False)
        disable_monitor_mode()


# Packet handler function
def packet_handler(pkt):
    global scanning

    if not scanning:
        return False

    if pkt.haslayer(Dot11):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info else "Unknown SSID"
        bssid = pkt[Dot11].addr2 if pkt[Dot11].addr2 else "Unknown BSSID"

        # Try extracting channel info safely
        try:
            channel = pkt[Dot11Elt:3].info[0]
        except Exception:
            channel = "Unknown"

        gui.log(f"[{datetime.now()}] SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")

        # Detect Rogue AP
        if ssid not in known_access_points:
            if bssid not in rogue_aps:
                gui.log(f"[ALERT] 🚨 Rogue AP Detected: SSID: {ssid}, BSSID: {bssid}, Channel: {channel}", "red")
                rogue_aps[bssid] = {"SSID": ssid, "Channel": channel}

        # Detect Evil Twin
        else:
            known_bssid = known_access_points[ssid]["BSSID"] if ssid in known_access_points else None
            if known_bssid and bssid != known_bssid:
                if ssid not in evil_twin_suspects:
                    evil_twin_suspects[ssid] = []
                evil_twin_suspects[ssid].append(bssid)
                gui.log(f"[ALERT] ⚠️ Evil Twin Detected: SSID: {ssid}, BSSID: {bssid}", "red")


# Launch GUI
if __name__ == "__main__":
    root = tk.Tk()
    gui = RogueAPDetectorGUI(root)
    root.mainloop()

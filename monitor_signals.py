#!/usr/bin/env python3

import sqlite3
import time
from datetime import datetime, timedelta
import threading
import os
import json
import subprocess
import sys
from queue import Queue

# Import these at the top level
import scapy.all as scapy
from bluepy import btle
import numpy as np
from sklearn.cluster import DBSCAN
import requests

# Configuration
class Config:
    ASSOCIATION_WINDOW = 5  # Time window for associating signals (in seconds)
    DEVICE_TIMEOUT = 300  # Time before a device is considered to have left (in seconds)
    BATCH_SIZE = 20  # Number of signals to process in a batch
    CLEANUP_INTERVAL = 60  # Interval for running the cleanup function (in seconds)
    BT_SCAN_INTERVAL = 30  # Interval between Bluetooth scans (in seconds)
    DATA_RETENTION_DAYS = 60  # Number of days to keep data
    DB_CLEANUP_INTERVAL = 86400  # Run database cleanup once a day (in seconds)
    REPORT_INTERVAL = 86400  # Generate report once a day (in seconds)
    SIGNAL_THRESHOLD = -70  # Only report signals stronger than this (adjust as needed)

    @classmethod
    def load_from_file(cls):
        try:
            with open('config.json', 'r') as f:
                config_data = json.load(f)
                for key, value in config_data.items():
                    if hasattr(cls, key):
                        setattr(cls, key, value)
            print("Configuration loaded from file.")
        except FileNotFoundError:
            print("Configuration file not found. Using default values.")
        except json.JSONDecodeError:
            print("Error decoding configuration file. Using default values.")

def check_requirements():
    required_tools = {
        'airmon-ng': 'aircrack-ng',
        'hcitool': 'bluez',
    }

    missing_tools = []

    for tool, package in required_tools.items():
        if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing_tools.append((tool, package))

    required_modules = ['scapy', 'bluepy', 'numpy', 'sklearn', 'requests']
    missing_modules = []

    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)

    if missing_tools or missing_modules:
        print("Error: Missing required tools or Python modules.")

        if missing_tools:
            print("Missing tools:")
            for tool, package in missing_tools:
                print(f"  - {tool} (install {package})")

            install = input("Do you want to install the missing tools? (y/n): ").lower().strip()
            if install == 'y':
                try:
                    subprocess.check_call(['sudo', 'apt-get', 'update'])
                    for _, package in missing_tools:
                        subprocess.check_call(['sudo', 'apt-get', 'install', '-y', package])
                    print("Tools installed successfully.")
                except subprocess.CalledProcessError:
                    print("Failed to install tools. Please install them manually.")
                    sys.exit(1)
            else:
                print("Please install the missing tools manually and try again.")
                sys.exit(1)

        if missing_modules:
            print("Missing Python modules:", ", ".join(missing_modules))
            install = input("Do you want to install the missing Python modules? (y/n): ").lower().strip()
            if install == 'y':
                try:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_modules)
                    print("Python modules installed successfully.")
                except subprocess.CalledProcessError:
                    print("Failed to install Python modules. Please install them manually.")
                    sys.exit(1)
            else:
                print("Please install the missing Python modules manually and try again.")
                sys.exit(1)

        # Recheck after installation
        if subprocess.call(['which', 'airmon-ng'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print("airmon-ng is still not available. Please ensure it's correctly installed.")
            sys.exit(1)

        for module in missing_modules:
            try:
                __import__(module)
            except ImportError:
                print(f"{module} is still not available. Please ensure it's correctly installed.")
                sys.exit(1)

    print("All required tools and modules are available.")

def setup_database():
    conn = sqlite3.connect('signals.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS wifi_signals
                 (id INTEGER PRIMARY KEY, type TEXT, ssid TEXT, bssid TEXT,
                  signal_strength INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    c.execute('''CREATE TABLE IF NOT EXISTS bluetooth_signals
                 (id INTEGER PRIMARY KEY, address TEXT, name TEXT, rssi INTEGER,
                  adv_data TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    conn.commit()
    conn.close()
    print("Database setup complete.")

# Global variables
conn = None
c = None
devices = {}
signal_queue = None
lock = None
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')

def send_webhook(data):
    try:
        response = requests.post(WEBHOOK_URL, json=data)
        print(f"Webhook response: {response.status_code}")
    except requests.RequestException as e:
        print(f"Webhook error: {e}")

def generate_device_id(wifi_data, bt_data):
    if wifi_data and bt_data:
        return f"combined_{wifi_data['bssid']}_{bt_data['address']}"
    elif wifi_data:
        return f"wifi_{wifi_data['bssid']}"
    else:
        return f"bt_{bt_data['address']}"

def update_device(wifi_data=None, bt_data=None):
    device_id = generate_device_id(wifi_data, bt_data)
    with lock:
        if device_id not in devices:
            devices[device_id] = {
                'wifi': wifi_data,
                'bluetooth': bt_data,
                'last_seen': datetime.now(),
                'appearances': [(datetime.now(), wifi_data['signal_strength'] if wifi_data else bt_data['rssi'])]
            }
        else:
            devices[device_id]['last_seen'] = datetime.now()
            if wifi_data:
                devices[device_id]['wifi'] = wifi_data
            if bt_data:
                devices[device_id]['bluetooth'] = bt_data
            devices[device_id]['appearances'].append((datetime.now(), wifi_data['signal_strength'] if wifi_data else bt_data['rssi']))

def wifi_sniff(packet):
    if packet.haslayer(scapy.Dot11):
        if packet.type == 0 and packet.subtype == 8:  # Beacon frame
            ssid = packet.info.decode(errors='replace')
            bssid = packet.addr2
            signal_strength = -(256-ord(packet.notdecoded[-4:-3]))  # Extract signal strength
            timestamp = datetime.now()
            signal_queue.put(('wifi', ssid, bssid, signal_strength, timestamp))

def bt_sniff():
    scanner = btle.Scanner()
    while True:
        try:
            devices = scanner.scan(10.0)  # Scan for 10 seconds
            for dev in devices:
                name = dev.getValueText(9) or "Unknown"
                addr = dev.addr
                rssi = dev.rssi
                adv_data = dev.getValueText(255) or ""
                timestamp = datetime.now()
                signal_queue.put(('bluetooth', name, addr, rssi, adv_data, timestamp))
        except btle.BTLEException as e:
            print(f"Bluetooth error: {e}")
        time.sleep(Config.BT_SCAN_INTERVAL)

def associate_signals(wifi_signals, bt_signals):
    associated_devices = []
    for wifi in wifi_signals:
        _, ssid, bssid, wifi_strength, wifi_time = wifi
        for bt in bt_signals:
            _, name, addr, bt_strength, _, bt_time = bt
            if abs((wifi_time - bt_time).total_seconds()) < Config.ASSOCIATION_WINDOW:
                associated_devices.append({
                    'wifi': {'ssid': ssid, 'bssid': bssid, 'signal_strength': wifi_strength},
                    'bluetooth': {'name': name, 'address': addr, 'rssi': bt_strength},
                    'timestamp': str(wifi_time)
                })
    return associated_devices

def process_signals():
    while True:
        wifi_signals = []
        bt_signals = []
        while not signal_queue.empty() and len(wifi_signals) + len(bt_signals) < Config.BATCH_SIZE:
            signal = signal_queue.get()
            if signal[0] == 'wifi':
                wifi_signals.append(signal)
            else:
                bt_signals.append(signal)

        if wifi_signals or bt_signals:
            associated_devices = associate_signals(wifi_signals, bt_signals)

            with conn:
                for signal in wifi_signals + bt_signals:
                    if signal[0] == 'wifi':
                        _, ssid, bssid, signal_strength, timestamp = signal
                        c.execute("INSERT INTO wifi_signals (type, ssid, bssid, signal_strength, timestamp) VALUES (?, ?, ?, ?, ?)",
                                  ('beacon', ssid, bssid, signal_strength, timestamp))
                        print(f"Wi-Fi Signal: SSID: {ssid}, BSSID: {bssid}, Strength: {signal_strength}, Timestamp: {timestamp}")
                    else:  # Bluetooth
                        _, name, addr, rssi, adv_data, timestamp = signal
                        c.execute("INSERT INTO bluetooth_signals (address, name, rssi, adv_data, timestamp) VALUES (?, ?, ?, ?, ?)",
                                  (addr, name, rssi, adv_data, timestamp))
                        print(f"Bluetooth Signal: Address: {addr}, Name: {name}, RSSI: {rssi}, Data: {adv_data}, Timestamp: {timestamp}")

            for device in associated_devices:
                update_device(wifi_data=device['wifi'], bt_data=device['bluetooth'])

            # For non-associated signals, update them separately
            for wifi in wifi_signals:
                if not any(d['wifi']['bssid'] == wifi[2] for d in associated_devices):
                    update_device(wifi_data={'ssid': wifi[1], 'bssid': wifi[2], 'signal_strength': wifi[3]})

            for bt in bt_signals:
                if not any(d['bluetooth']['address'] == bt[2] for d in associated_devices):
                    update_device(bt_data={'name': bt[1], 'address': bt[2], 'rssi': bt[3], 'adv_data': bt[4]})

        time.sleep(1)  # Small delay to prevent tight looping

def cleanup_devices():
    while True:
        with lock:
            current_time = datetime.now()
            for device_id, info in list(devices.items()):
                if (current_time - info['last_seen']).total_seconds() > Config.DEVICE_TIMEOUT:
                    del devices[device_id]

        time.sleep(Config.CLEANUP_INTERVAL)

def cleanup_old_data():
    while True:
        try:
            with conn:
                cutoff_date = datetime.now() - timedelta(days=Config.DATA_RETENTION_DAYS)
                c.execute("DELETE FROM wifi_signals WHERE timestamp < ?", (cutoff_date,))
                c.execute("DELETE FROM bluetooth_signals WHERE timestamp < ?", (cutoff_date,))
                print(f"Deleted data older than {Config.DATA_RETENTION_DAYS} days. Rows affected: {c.rowcount}")
        except sqlite3.Error as e:
            print(f"Database error during cleanup: {e}")

        time.sleep(Config.DB_CLEANUP_INTERVAL)

def generate_daily_report():
    while True:
        time.sleep(Config.REPORT_INTERVAL)

        with lock:
            current_time = datetime.now()
            report_start_time = current_time - timedelta(seconds=Config.REPORT_INTERVAL)

            new_devices = []
            active_devices = []

            for device_id, info in devices.items():
                if info['last_seen'] > report_start_time:
                    device_info = {
                        'device_id': device_id,
                        'last_seen': str(info['last_seen']),
                        'appearances': len([a for a in info['appearances'] if a[0] > report_start_time])
                    }

                    if info['wifi'] and info['wifi']['signal_strength'] > Config.SIGNAL_THRESHOLD:
                        device_info['wifi'] = info['wifi']

                    if info['bluetooth'] and info['bluetooth']['rssi'] > Config.SIGNAL_THRESHOLD:
                        device_info['bluetooth'] = info['bluetooth']

                    if info['last_seen'] - timedelta(seconds=Config.REPORT_INTERVAL) < report_start_time:
                        new_devices.append(device_info)
                    else:
                        active_devices.append(device_info)

            report = {
                'report_period': {
                    'start': str(report_start_time),
                    'end': str(current_time)
                },
                'new_devices': new_devices,
                'active_devices': active_devices,
                'total_devices_seen': len(new_devices) + len(active_devices)
            }

            send_webhook({'event': 'daily_report', 'report': report})
            print(f"Daily report sent. New devices: {len(new_devices)}, Active devices: {len(active_devices)}")

def get_wifi_interface():
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = [line.split()[0] for line in result.stdout.split('\n') if 'IEEE 802.11' in line]
        if interfaces:
            return interfaces[0]
    except Exception as e:
        print(f"Error detecting Wi-Fi interface: {e}")
    return None

def main():
    global conn, c, signal_queue, lock

    print("Checking requirements...")
    check_requirements()

    print("Setting up database...")
    setup_database()

    Config.load_from_file()

    conn = sqlite3.connect('signals.db', check_same_thread=False)
    c = conn.cursor()
    signal_queue = Queue()
    lock = threading.Lock()

    # Check for Wi-Fi interface
    wifi_interface = get_wifi_interface()
    if not wifi_interface:
        wifi_interface = input("Wi-Fi interface not detected. Please enter the name of your Wi-Fi interface: ")

    print(f"Using Wi-Fi interface: {wifi_interface}")

    print("Starting Wi-Fi Sniffing...")
    wifi_thread = threading.Thread(target=lambda: scapy.sniff(iface=wifi_interface, prn=wifi_sniff, store=0))
    wifi_thread.start()

    print("Starting Bluetooth Sniffing...")
    bt_thread = threading.Thread(target=bt_sniff)
    bt_thread.start()

    print("Starting signal processing...")
    process_thread = threading.Thread(target=process_signals)
    process_thread.start()

    print("Starting device cleanup...")
    cleanup_thread = threading.Thread(target=cleanup_devices)
    cleanup_thread.start()

    print("Starting database cleanup...")
    db_cleanup_thread = threading.Thread(target=cleanup_old_data)
    db_cleanup_thread.start()

    print("Starting daily report generation...")
    report_thread = threading.Thread(target=generate_daily_report)
    report_thread.start()

    try:
        wifi_thread.join()
        bt_thread.join()
        process_thread.join()
        cleanup_thread.join()
        db_cleanup_thread.join()
        report_thread.join()
    except KeyboardInterrupt:
        print("\nStopping threads...")
    finally:
        conn.close()
        print("Database connection closed. Exiting.")

if __name__ == "__main__":
    main()

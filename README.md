# SigSentry: Advanced Wi-Fi and Bluetooth Signal Monitoring Tool

SigSentry is a powerful, open-source tool designed for comprehensive monitoring of Wi-Fi and Bluetooth signals in your environment. It offers real-time detection, data logging, and daily reporting capabilities, making it ideal for network administrators, security researchers, and IoT enthusiasts.

## Features

- Real-time Wi-Fi and Bluetooth signal detection
- Automatic association of Wi-Fi and Bluetooth signals from the same device
- SQLite database storage for captured signal data
- Daily report generation via webhook
- Automatic cleanup of old data
- Configurable settings via JSON file
- Cross-platform compatibility (Linux-based systems)

## Prerequisites

- Python 3.7+
- Raspberry Pi or Linux-based system with Wi-Fi and Bluetooth capabilities
- Root/sudo privileges

## Installation

1. Clone the repository:
```
   git clone https://github.com/yourusername/SigSentry.git
   cd SigSentry
```
2. Install required packages:
```
   sudo pip3 install scapy bluepy numpy scikit-learn requests
```
   3. Install system dependencies:
```
sudo apt-get update
sudo apt-get install -y aircrack-ng bluez
```

## Configuration

1. Copy the example configuration file:
cp config.example.json config.json

3. Edit config.json to adjust settings as needed:
```
{
    "ASSOCIATION_WINDOW": 5,
    "DEVICE_TIMEOUT": 300,
    "BATCH_SIZE": 20,
    "CLEANUP_INTERVAL": 60,
    "BT_SCAN_INTERVAL": 30,
    "DATA_RETENTION_DAYS": 60,
    "DB_CLEANUP_INTERVAL": 86400,
    "REPORT_INTERVAL": 86400,
    "SIGNAL_THRESHOLD": -70
}
```

Set the webhook URL for daily reports:
```
export WEBHOOK_URL="https://your-webhook-url.com"
```

## Usage
Run the script with sudo privileges:
```
sudo python3 monitor_signals.py
```
The script will:

Check for and offer to install any missing requirements
Set up the SQLite database if it doesn't exist
Detect the Wi-Fi interface or prompt for manual input
Start monitoring Wi-Fi and Bluetooth signals
Process and store detected signals
Generate daily reports

## Contributing
Contributions to SigSentry are welcome! Please feel free to submit a Pull Request.

## Disclaimer
This tool is intended for educational and research purposes only. Always respect privacy laws and obtain necessary permissions before monitoring any networks or devices you do not own or have explicit authorization to test.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

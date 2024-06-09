# Network Packet Analyzer
- A packet sniffer that captures and analyzes network packets.
- Displays relevant information such as:
    * source and destination IP addresses
    * protocols
    * payload data

## Requirements
- Python 3
- `scapy` module

## Installation
Before running the program, install the required dependencies:

```sh
pip install -r requirements.txt
```

- If you want to use this tool on Windows using Scapy, you'll need to install a packet capture libraries installed.
    * Install Npcap from here: https://npcap.com/

* To run the program:
```sh
python sniffer.py <interface>
```

## Note
- **This code is intended for educational purposes only.**
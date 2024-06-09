import sys
from scapy.all import *

def handle_packet(packet, log):
    """
    Processes a packet and logs relevant information to the specified log file.

    Args:
        packet: The packet to process.
        log: The file object where log entries will be written.

    Extracts relevant information from the packet such as source and destination IP addresses,
    protocols, and payload data, and writes this information to the log file.
    """
    # Check if the packet contains TCP layer
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Extract source and destination ports
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        protocol = "TCP"

        # Extract payload data
        # payload = packet[Raw].load if Raw in packet else None
        payload = extract_payload(packet)

        # Write packet info to log file
        log.write(f"{protocol} Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port} Protocol: {protocol}, Payload: {payload}\n")

def extract_payload(packet):
    """
    Extracts the payload data from the packet and returns it in a readable format.

    Args:
        packet: The packet containing the payload data.

    Returns:
        str: The payload data in a readable format.
    """
    if Raw in packet:
        # Check if payload is HTTP
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return str(packet[TCP].payload)
        else:
            # return raw payload
            return packet[Raw].load

def main(interface):
    """
    Main function to start packet sniffing on the specified interface.

    Args:
        interface: The network interface to sniff on.

    Creates a log file named based on the interface and starts sniffing packets
    on the specified interface. Logs TCP connection details using the handle_packet function.
    """
    # Create log filename based on interface
    logfile_name = f"sniffer_{interface}_log.txt"

    with open(logfile_name, 'w') as logfile:
        try:
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

    
if __name__ == '__main__':
    """
    Entry point of the script. Ensures the correct usage and starts the main function.

    Expects a single command line argument specifying the network interface to sniff on.
    If the argument is not provided, it prints usage information and exits.
    """
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)
    main(sys.argv[1])
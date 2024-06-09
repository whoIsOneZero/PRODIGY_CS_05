import sys
from scapy.all import *

def handle_packet(packet, log):
    """
    Processes a packet and logs TCP connection details to the specified log file.

    Args:
        packet: The packet to process.
        log: The file object where log entries will be written.

    Checks if the packet contains a TCP layer. If it does, extracts the source
    and destination IP addresses and ports, and writes this information to the log file.
    """
    # Check if the packet contains TCP layer
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Extract source and destination ports
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Write packet info to log file
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

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
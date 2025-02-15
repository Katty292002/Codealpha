from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime

# Global list to store packets
captured_packets = []

# Packet handler function
def process_packet(packet):
    packet_info = {}
    
    if IP in packet:  # Check if packet has an IP layer
        packet_info["Source IP"] = packet[IP].src
        packet_info["Destination IP"] = packet[IP].dst
        packet_info["Protocol"] = packet[IP].proto

        if TCP in packet:
            packet_info["Protocol"] = "TCP"
            packet_info["Source Port"] = packet[TCP].sport
            packet_info["Destination Port"] = packet[TCP].dport
        
        elif UDP in packet:
            packet_info["Protocol"] = "UDP"
            packet_info["Source Port"] = packet[UDP].sport
            packet_info["Destination Port"] = packet[UDP].dport

        elif ICMP in packet:
            packet_info["Protocol"] = "ICMP"

        # Print captured packet details
        print(f"{packet_info['Source IP']} --> {packet_info['Destination IP']} | {packet_info['Protocol']}")
        
        # Store packet
        captured_packets.append(packet)

# Start packet sniffing
def start_sniffing(interface=None, packet_count=50, save_file="captured_traffic.pcap"):
    print(f"[*] Starting packet capture on {interface if interface else 'default interface'}...")
    sniff(prn=process_packet, iface=interface, count=packet_count, store=True)

    # Save captured packets to a file
    wrpcap(save_file, captured_packets)
    print(f"[*] Packets saved to {save_file}")

# Run the sniffer
if __name__ == "__main__":
    interface = input("Enter network interface (leave blank for default): ")
    start_sniffing(interface=interface if interface else None)

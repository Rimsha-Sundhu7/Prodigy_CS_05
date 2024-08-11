import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        
        # Map protocol numbers to names
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol_name = protocol_map.get(protocol, "Other")

        print(f"\n[+] Packet Captured:")
        print(f"    Source IP: {ip_layer.src}")
        print(f"    Destination IP: {ip_layer.dst}")
        print(f"    Protocol: {protocol_name}")

        # Display relevant payload data based on the protocol
        if protocol == 6:  # TCP
            tcp_layer = packet[TCP]
            print(f"    Source Port: {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
            print(f"    Payload: {bytes(tcp_layer.payload)}")
        
        elif protocol == 17:  # UDP
            udp_layer = packet[UDP]
            print(f"    Source Port: {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")
            print(f"    Payload: {bytes(udp_layer.payload)}")
        
        elif protocol == 1:  # ICMP
            icmp_layer = packet[ICMP]
            print(f"    Type: {icmp_layer.type}")
            print(f"    Code: {icmp_layer.code}")
            print(f"    Payload: {bytes(icmp_layer.payload)}")
        
        else:
            print(f"    Payload: {bytes(packet[IP].payload)}")

def sniff_packets(interface):
    print(f"[*] Starting packet sniffing on {interface}...")
    try:
        # Use sniff to capture packets
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except PermissionError:
        print("[-] Permission denied: You need to run this script with elevated privileges.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    # Replace 'eth0' with your actual network interface name
    sniff_packets('eth0')

    # Ensure you use this tool ethically and only on networks you own or have explicit permission to analyze.

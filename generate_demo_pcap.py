"""
Utility script to generate a synthetic PCAP with normal traffic,
an ARP spoofing attack, a TCP port scan, and a TCP SYN flood.
"""
import time
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import wrpcap


def generate_demo_traffic(output_file: str = "demo.pcap"):
    packets = []
    base_time = time.time()

    # 1. Background normal web and DNS traffic (200 packets)
    for i in range(200):
        t = base_time + (i * 0.005)
        # DNS query & response
        dns_req = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=50000 + (i % 100), dport=53)
        dns_req.time = t
        packets.append(dns_req)

        # Legitimate HTTP/HTTPS handshakes (SYN + ACK)
        syn = Ether() / IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=60000 + (i % 100), dport=443, flags="S")
        syn.time = t + 0.001
        ack = Ether() / IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=60000 + (i % 100), dport=443, flags="A")
        ack.time = t + 0.002
        packets.extend([syn, ack])

    # 2. ARP Poisoning Attack
    # Legitimate router ARP reply
    legit_arp = Ether() / ARP(op=2, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1", pdst="192.168.1.100")
    legit_arp.time = base_time + 1.5
    packets.append(legit_arp)

    # Rogue ARP reply claiming router IP with attacker MAC
    spoofed_arp = Ether() / ARP(op=2, hwsrc="de:ad:be:ef:00:01", psrc="192.168.1.1", pdst="192.168.1.100")
    spoofed_arp.time = base_time + 1.8
    packets.append(spoofed_arp)

    # 3. TCP Port Scan Attack (Probing 30 ports within 1.5 seconds)
    scan_time = base_time + 2.5
    for p in range(1, 35):
        scan_pkt = Ether() / IP(src="10.0.0.66", dst="192.168.1.50") / TCP(sport=55555, dport=p, flags="S")
        scan_pkt.time = scan_time + (p * 0.03)
        packets.append(scan_pkt)

    # 4. TCP SYN Flood Attack (60 pure SYNs to web server without ACKs)
    flood_time = base_time + 4.0
    for s in range(65):
        flood_pkt = Ether() / IP(src=f"172.16.0.{10 + (s % 50)}", dst="192.168.1.10") / TCP(sport=10000 + s, dport=80, flags="S")
        flood_pkt.time = flood_time + (s * 0.01)
        packets.append(flood_pkt)

    wrpcap(output_file, packets)
    print(f"Generated {len(packets)} synthetic packets into '{output_file}'.")


if __name__ == "__main__":
    generate_demo_traffic()

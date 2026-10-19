import time
from typing import Dict, Any
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet


def decode_frame(packet: Packet) -> Dict[str, Any]:
    """
    Decodes Ethernet, ARP, IPv4, TCP, UDP, and ICMP layers from raw packet.
    Does NOT convert raw bytes to hex upfront to maintain high throughput.
    """
    pkt_time = getattr(packet, "time", None)
    frame_timestamp = float(pkt_time) if pkt_time is not None else time.time()

    frame_data = {
        "timestamp": frame_timestamp,
        "length": len(packet),
        "raw_packet": packet,
        "eth": None,
        "arp": None,
        "ip": None,
        "transport": None,
    }

    if packet.haslayer(Ether):
        eth = packet[Ether]
        frame_data["eth"] = {
            "src_mac": eth.src,
            "dst_mac": eth.dst,
            "type": eth.type,
        }

    if packet.haslayer(ARP):
        arp = packet[ARP]
        frame_data["arp"] = {
            "op": arp.op,
            "hwsrc": arp.hwsrc,
            "psrc": arp.psrc,
            "hwdst": arp.hwdst,
            "pdst": arp.pdst,
        }

    if packet.haslayer(IP):
        ip = packet[IP]
        frame_data["ip"] = {
            "src": ip.src,
            "dst": ip.dst,
            "proto": ip.proto,
            "ttl": ip.ttl,
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)
            frame_data["transport"] = {
                "type": "TCP",
                "sport": tcp.sport,
                "dport": tcp.dport,
                "flags": flags,
                "is_syn": "S" in flags and "A" not in flags,
                "is_ack": "A" in flags,
            }
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            frame_data["transport"] = {
                "type": "UDP",
                "sport": udp.sport,
                "dport": udp.dport,
            }
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            frame_data["transport"] = {
                "type": "ICMP",
                "type_code": icmp.type,
                "code": icmp.code,
            }

    return frame_data


def extract_hex(frame: Dict[str, Any]) -> str:
    """Lazily converts raw packet to hex string only when an alert fires."""
    raw = frame.get("raw_packet")
    return bytes(raw).hex() if raw else ""

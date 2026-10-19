import os
import time
import pytest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import wrpcap

from sniffer.decoder import decode_frame, extract_hex
from sniffer.detector import AnomalyDetector
from sniffer.database import AlertDatabase
from sniffer.runner import PacketCaptureRunner


def test_decoder_layers():
    # 1. TCP Packet
    tcp_pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
              IP(src="192.168.1.10", dst="192.168.1.20") / \
              TCP(sport=12345, dport=80, flags="S")

    decoded = decode_frame(tcp_pkt)
    assert decoded["eth"]["src_mac"] == "aa:bb:cc:dd:ee:01"
    assert decoded["ip"]["src"] == "192.168.1.10"
    assert decoded["transport"]["type"] == "TCP"
    assert decoded["transport"]["dport"] == 80
    assert decoded["transport"]["is_syn"] is True
    assert decoded["transport"]["is_ack"] is False
    assert len(extract_hex(decoded)) > 0

    # 2. UDP Packet
    udp_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
    decoded_udp = decode_frame(udp_pkt)
    assert decoded_udp["transport"]["type"] == "UDP"
    assert decoded_udp["transport"]["dport"] == 53

    # 3. ICMP Packet
    icmp_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
    decoded_icmp = decode_frame(icmp_pkt)
    assert decoded_icmp["transport"]["type"] == "ICMP"
    assert decoded_icmp["transport"]["type_code"] == 8

    # 4. ARP Packet
    arp_pkt = Ether() / ARP(op=2, hwsrc="11:22:33:44:55:66", psrc="192.168.1.1")
    decoded_arp = decode_frame(arp_pkt)
    assert decoded_arp["arp"]["op"] == 2
    assert decoded_arp["arp"]["hwsrc"] == "11:22:33:44:55:66"
    assert decoded_arp["arp"]["psrc"] == "192.168.1.1"


def test_arp_spoof_detection():
    detector = AnomalyDetector(alert_cooldown_sec=2.0)

    # Initial legitimate ARP reply: 192.168.1.1 is at aa:aa:aa:aa:aa:aa
    pkt1 = Ether() / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:aa", psrc="192.168.1.1", pdst="192.168.1.100")
    frame1 = decode_frame(pkt1)
    alerts1 = detector.inspect_frame(frame1)
    assert len(alerts1) == 0

    # Malicious ARP reply: 192.168.1.1 claims to be at bb:bb:bb:bb:bb:bb (Attacker MAC)
    pkt2 = Ether() / ARP(op=2, hwsrc="bb:bb:bb:bb:bb:bb", psrc="192.168.1.1", pdst="192.168.1.100")
    frame2 = decode_frame(pkt2)
    alerts2 = detector.inspect_frame(frame2)
    assert len(alerts2) == 1
    assert alerts2[0]["attack_type"] == "ARP_SPOOFING"
    assert alerts2[0]["source_mac"] == "bb:bb:bb:bb:bb:bb"

    # Throttled duplicate attempt
    alerts3 = detector.inspect_frame(frame2)
    assert len(alerts3) == 0


def test_syn_flood_with_ack_ratio():
    detector = AnomalyDetector(syn_threshold_per_sec=30, syn_ack_ratio_threshold=0.10)
    base_time = time.time()

    # 1. Legitimate traffic: 35 SYNs matched with 35 ACKs
    for i in range(35):
        pkt_syn = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=1000 + i, dport=443, flags="S")
        pkt_syn.time = base_time + (i * 0.01)
        pkt_ack = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=1000 + i, dport=443, flags="A")
        pkt_ack.time = base_time + (i * 0.01)

        f_syn = decode_frame(pkt_syn)
        f_ack = decode_frame(pkt_ack)
        detector.inspect_frame(f_ack)
        alerts = detector.inspect_frame(f_syn)
        assert len(alerts) == 0  # No alert because ACK ratio is ~100%

    # 2. Attack traffic: 35 pure SYNs with 0 ACKs
    attack_time = base_time + 5.0  # Outside previous 1s window
    alerts_fired = []
    for i in range(35):
        pkt_syn = Ether() / IP(src="10.0.0.99", dst="10.0.0.2") / TCP(sport=2000 + i, dport=80, flags="S")
        pkt_syn.time = attack_time + (i * 0.01)
        f_syn = decode_frame(pkt_syn)
        alerts = detector.inspect_frame(f_syn)
        if alerts:
            alerts_fired.extend(alerts)

    assert len(alerts_fired) == 1
    assert alerts_fired[0]["attack_type"] == "TCP_SYN_FLOOD"
    assert alerts_fired[0]["target_ip"] == "10.0.0.2"


def test_port_scan_detection():
    detector = AnomalyDetector(port_scan_threshold_ports=20, port_scan_window_sec=3.0)
    now = time.time()

    # Probe 22 distinct ports from source 192.168.1.50
    alerts_fired = []
    for port in range(1, 23):
        pkt = Ether() / IP(src="192.168.1.50", dst="192.168.1.10") / TCP(sport=40000, dport=port, flags="S")
        pkt.time = now + (port * 0.02)
        frame = decode_frame(pkt)
        alerts = detector.inspect_frame(frame)
        if alerts:
            alerts_fired.extend(alerts)

    assert len(alerts_fired) == 1
    assert alerts_fired[0]["attack_type"] == "PORT_SCAN"
    assert alerts_fired[0]["source_ip"] == "192.168.1.50"


def test_database_batch_persistence(tmp_path):
    db_file = str(tmp_path / "test_alerts.db")
    db = AlertDatabase(db_path=db_file)

    test_alerts = [
        {
            "attack_type": "TCP_SYN_FLOOD",
            "source_ip": "10.0.0.99",
            "source_mac": "aa:bb:cc:dd:ee:ff",
            "target_ip": "10.0.0.1",
            "target_port": 80,
            "description": "SYN flood test alert 1",
            "packet_hex": "deadbeef01",
        },
        {
            "attack_type": "PORT_SCAN",
            "source_ip": "10.0.0.105",
            "source_mac": "aa:bb:cc:dd:ee:02",
            "target_ip": "10.0.0.1",
            "target_port": 443,
            "description": "Port scan test alert 2",
            "packet_hex": "deadbeef02",
        },
    ]

    db.log_alerts_batch(test_alerts)
    saved = db.get_recent_alerts(limit=10)

    assert len(saved) == 2
    assert saved[0]["attack_type"] == "PORT_SCAN"
    assert saved[1]["attack_type"] == "TCP_SYN_FLOOD"


def test_runner_offline_pcap_replay(tmp_path):
    pcap_path = str(tmp_path / "synthetic_traffic.pcap")
    db_path = str(tmp_path / "pcap_alerts.db")

    packets = []
    # Regular traffic
    packets.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53))
    packets.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())

    # ARP Poison sequence
    packets.append(Ether() / ARP(op=2, hwsrc="11:11:11:11:11:11", psrc="192.168.1.1", pdst="192.168.1.100"))
    packets.append(Ether() / ARP(op=2, hwsrc="22:22:22:22:22:22", psrc="192.168.1.1", pdst="192.168.1.100"))

    wrpcap(pcap_path, packets)

    runner = PacketCaptureRunner(pcap_file=pcap_path, db_path=db_path)
    runner.run()

    assert runner.stats["packets_captured"] == 4
    assert runner.stats["packets_processed"] == 4
    assert runner.stats["packets_dropped"] == 0
    assert runner.stats["alerts_triggered"] == 1

    db = AlertDatabase(db_path=db_path)
    alerts = db.get_recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "ARP_SPOOFING"

import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
from sniffer.decoder import extract_hex


class AnomalyDetector:
    def __init__(
        self,
        syn_threshold_per_sec: int = 50,
        syn_ack_ratio_threshold: float = 0.10,
        port_scan_threshold_ports: int = 25,
        port_scan_window_sec: float = 5.0,
        alert_cooldown_sec: float = 5.0,
    ):
        self.syn_threshold_per_sec = syn_threshold_per_sec
        self.syn_ack_ratio_threshold = syn_ack_ratio_threshold
        self.port_scan_threshold_ports = port_scan_threshold_ports
        self.port_scan_window_sec = port_scan_window_sec
        self.alert_cooldown_sec = alert_cooldown_sec

        # IP -> MAC mapping
        self.ip_to_mac_table: Dict[str, str] = {}

        # Sliding window SYN and ACK histories per destination IP
        self.syn_history: Dict[str, deque] = defaultdict(deque)
        self.ack_history: Dict[str, deque] = defaultdict(deque)

        # Port scan history: src_ip -> deque of (timestamp, dst_port)
        self.port_scan_history: Dict[str, deque] = defaultdict(deque)

        # Alert Throttling: alert_key -> last_alert_time
        self.alert_cooldowns: Dict[str, float] = {}

        # Last sweep timestamp for memory eviction
        self.last_cleanup_time: float = 0.0

    def _should_throttle(self, alert_key: str, now: float) -> bool:
        last_time = self.alert_cooldowns.get(alert_key, 0.0)
        if now - last_time < self.alert_cooldown_sec:
            return True
        self.alert_cooldowns[alert_key] = now
        return False

    def _evict_stale_state(self, now: float):
        """Periodic sweep to prevent unbounded memory growth."""
        if now - self.last_cleanup_time < 10.0:
            return
        self.last_cleanup_time = now

        # Evict empty deques from syn/ack tracking
        for table in (self.syn_history, self.ack_history):
            stale_keys = [k for k, q in table.items() if not q or q[-1] < now - 2.0]
            for k in stale_keys:
                del table[k]

        # Evict empty deques from port scan tracking
        stale_scanners = [k for k, q in self.port_scan_history.items() if not q or q[-1][0] < now - self.port_scan_window_sec]
        for k in stale_scanners:
            del self.port_scan_history[k]

        # Evict expired cooldowns
        expired_cooldowns = [k for k, t in self.alert_cooldowns.items() if now - t > self.alert_cooldown_sec * 2]
        for k in expired_cooldowns:
            del self.alert_cooldowns[k]

    def check_arp_spoof(self, frame: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        arp = frame.get("arp")
        if not arp or arp.get("op") != 2:
            return None

        ip = arp["psrc"]
        mac = arp["hwsrc"].lower()
        now = frame["timestamp"]

        if ip in self.ip_to_mac_table:
            known_mac = self.ip_to_mac_table[ip]
            if known_mac != mac:
                alert_key = f"ARP_SPOOF:{ip}:{mac}"
                if self._should_throttle(alert_key, now):
                    return None
                return {
                    "attack_type": "ARP_SPOOFING",
                    "source_ip": ip,
                    "source_mac": mac,
                    "target_ip": arp.get("pdst"),
                    "description": f"ARP poisoning detected! IP {ip} changed MAC from {known_mac} to {mac}",
                    "packet_hex": extract_hex(frame),
                }
        else:
            self.ip_to_mac_table[ip] = mac

        return None

    def check_syn_flood(self, frame: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip = frame.get("ip")
        transport = frame.get("transport")
        if not ip or not transport or transport.get("type") != "TCP":
            return None

        dst_ip = ip["dst"]
        now = frame["timestamp"]

        # Track ACKs for completion ratio
        if transport.get("is_ack"):
            q_ack = self.ack_history[dst_ip]
            q_ack.append(now)
            while q_ack and q_ack[0] < now - 1.0:
                q_ack.popleft()

        # Track SYNs
        if transport.get("is_syn"):
            q_syn = self.syn_history[dst_ip]
            q_syn.append(now)
            while q_syn and q_syn[0] < now - 1.0:
                q_syn.popleft()

            syn_count = len(q_syn)
            if syn_count >= self.syn_threshold_per_sec:
                # Evict stale ACKs in same 1-second window before computing ratio
                q_ack = self.ack_history[dst_ip]
                while q_ack and q_ack[0] < now - 1.0:
                    q_ack.popleft()
                ack_count = len(q_ack)
                ack_ratio = ack_count / syn_count if syn_count > 0 else 1.0

                if ack_ratio < self.syn_ack_ratio_threshold:
                    alert_key = f"SYN_FLOOD:{dst_ip}"
                    if self._should_throttle(alert_key, now):
                        return None
                    return {
                        "attack_type": "TCP_SYN_FLOOD",
                        "source_ip": ip["src"],
                        "source_mac": frame.get("eth", {}).get("src_mac"),
                        "target_ip": dst_ip,
                        "target_port": transport.get("dport"),
                        "description": f"SYN flood against {dst_ip}: {syn_count} SYNs/sec with {ack_ratio:.1%} ACK ratio",
                        "packet_hex": extract_hex(frame),
                    }

        return None

    def check_port_scan(self, frame: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip = frame.get("ip")
        transport = frame.get("transport")
        if not ip or not transport or transport.get("type") != "TCP":
            return None

        src_ip = ip["src"]
        dport = transport.get("dport")
        if dport is None:
            return None
        now = frame["timestamp"]

        q = self.port_scan_history[src_ip]
        q.append((now, dport))

        while q and q[0][0] < now - self.port_scan_window_sec:
            q.popleft()

        unique_ports = {port for _, port in q}
        if len(unique_ports) >= self.port_scan_threshold_ports:
            alert_key = f"PORT_SCAN:{src_ip}"
            if self._should_throttle(alert_key, now):
                return None
            return {
                "attack_type": "PORT_SCAN",
                "source_ip": src_ip,
                "source_mac": frame.get("eth", {}).get("src_mac"),
                "target_ip": ip["dst"],
                "target_port": dport,
                "description": f"Port scan from {src_ip}: {len(unique_ports)} unique ports in {self.port_scan_window_sec}s",
                "packet_hex": extract_hex(frame),
            }

        return None

    def inspect_frame(self, frame: Dict[str, Any]) -> List[Dict[str, Any]]:
        now = frame.get("timestamp", time.time())
        self._evict_stale_state(now)

        alerts = []
        arp_alert = self.check_arp_spoof(frame)
        if arp_alert:
            alerts.append(arp_alert)

        syn_alert = self.check_syn_flood(frame)
        if syn_alert:
            alerts.append(syn_alert)

        scan_alert = self.check_port_scan(frame)
        if scan_alert:
            alerts.append(scan_alert)

        return alerts

import queue
import threading
import time
from typing import Optional, Callable, Dict, Any, List
from scapy.all import sniff, PcapReader, Packet
from scapy.error import Scapy_Exception

from sniffer.decoder import decode_frame
from sniffer.detector import AnomalyDetector
from sniffer.database import AlertDatabase


class PacketCaptureRunner:
    """
    Decoupled Producer-Consumer Packet Capture & Analysis Runner.
    Thread 1 (Producer): Captures frames from live interface or PCAP and enqueues raw packets.
    Thread 2 (Consumer): Decodes frames, runs anomaly heuristics, and batches forensic DB writes.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_limit: Optional[int] = None,
        queue_maxsize: int = 10000,
        db_path: str = "alerts.db",
        detector: Optional[AnomalyDetector] = None,
        on_stats_update: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.packet_limit = packet_limit
        self.queue: queue.Queue = queue.Queue(maxsize=queue_maxsize)

        self.db = AlertDatabase(db_path=db_path)
        self.detector = detector or AnomalyDetector()
        self.on_stats_update = on_stats_update
        self.on_alert = on_alert

        self._stop_event = threading.Event()
        self._producer_thread: Optional[threading.Thread] = None
        self._consumer_thread: Optional[threading.Thread] = None

        self.stats_lock = threading.Lock()
        self.stats: Dict[str, Any] = {
            "packets_captured": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "alerts_triggered": 0,
            "current_pps": 0.0,
            "start_time": 0.0,
            "protocol_counts": {
                "TCP": 0,
                "UDP": 0,
                "ICMP": 0,
                "ARP": 0,
                "OTHER": 0,
            },
        }

    def _producer_worker(self):
        """Producer thread: Captures raw frames and enqueues them."""
        def packet_handler(pkt: Packet):
            if self._stop_event.is_set():
                return True  # Stop Scapy sniff

            with self.stats_lock:
                self.stats["packets_captured"] += 1
                if self.packet_limit and self.stats["packets_captured"] >= self.packet_limit:
                    self._stop_event.set()

            try:
                self.queue.put_nowait(pkt)
            except queue.Full:
                with self.stats_lock:
                    self.stats["packets_dropped"] += 1

            return False

        try:
            if self.pcap_file:
                # Offline replay mode
                with PcapReader(self.pcap_file) as pcap_reader:
                    for pkt in pcap_reader:
                        if self._stop_event.is_set():
                            break
                        packet_handler(pkt)
            else:
                # Live network interface capture
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=packet_handler,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
        except (Scapy_Exception, PermissionError, OSError) as e:
            # Clean diagnostic reporting for Windows/driver permission issues
            err_msg = (
                f"\n[!] Capture failure on interface '{self.interface}': {e}\n"
                "[!] Ensure Npcap is installed in WinPcap-compatible mode and the terminal is running as Administrator.\n"
                "[!] Alternatively, use offline PCAP replay mode: --pcap <path.pcap>\n"
            )
            print(err_msg)
        finally:
            self._stop_event.set()
            # Push sentinel to unblock consumer
            self.queue.put(None)

    def _consumer_worker(self):
        """Consumer thread: Decodes frames, evaluates heuristics, and writes alerts."""
        pending_alerts: List[Dict[str, Any]] = []
        last_flush_time = time.time()
        last_stat_time = time.time()
        stat_packet_count = 0

        while True:
            try:
                pkt = self.queue.get(timeout=0.1)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
                continue

            if pkt is None:
                # Sentinel reached
                self.queue.task_done()
                break

            now = time.time()
            stat_packet_count += 1
            if now - last_stat_time >= 1.0:
                elapsed = now - last_stat_time
                with self.stats_lock:
                    self.stats["current_pps"] = stat_packet_count / elapsed
                stat_packet_count = 0
                last_stat_time = now

            # 1. Decode Frame
            frame = decode_frame(pkt)

            # 2. Update protocol stats
            proto = "OTHER"
            if frame.get("arp"):
                proto = "ARP"
            elif frame.get("transport"):
                proto = frame["transport"].get("type", "OTHER")

            with self.stats_lock:
                self.stats["packets_processed"] += 1
                if proto in self.stats["protocol_counts"]:
                    self.stats["protocol_counts"][proto] += 1
                else:
                    self.stats["protocol_counts"]["OTHER"] += 1

            # 3. Anomaly Detection
            alerts = self.detector.inspect_frame(frame)
            if alerts:
                with self.stats_lock:
                    self.stats["alerts_triggered"] += len(alerts)
                for alert in alerts:
                    pending_alerts.append(alert)
                    if self.on_alert:
                        self.on_alert(alert)

            # 4. Batch DB Commit Check
            if len(pending_alerts) >= 20 or (pending_alerts and now - last_flush_time >= 0.5):
                self.db.log_alerts_batch(pending_alerts)
                pending_alerts.clear()
                last_flush_time = now

            # 5. Periodic Stats Callback
            if self.on_stats_update and self.stats["packets_processed"] % 25 == 0:
                with self.stats_lock:
                    stats_snapshot = dict(self.stats)
                    stats_snapshot["protocol_counts"] = dict(self.stats["protocol_counts"])
                self.on_stats_update(stats_snapshot)

            self.queue.task_done()

        # Flush any remaining alerts on exit
        if pending_alerts:
            self.db.log_alerts_batch(pending_alerts)
            pending_alerts.clear()

        # Final stats update
        if self.on_stats_update:
            with self.stats_lock:
                stats_snapshot = dict(self.stats)
                stats_snapshot["protocol_counts"] = dict(self.stats["protocol_counts"])
            self.on_stats_update(stats_snapshot)

    def start(self):
        """Starts both capture and analysis threads."""
        self._stop_event.clear()
        with self.stats_lock:
            self.stats["start_time"] = time.time()

        self._producer_thread = threading.Thread(target=self._producer_worker, daemon=True)
        self._consumer_thread = threading.Thread(target=self._consumer_worker, daemon=True)

        self._consumer_thread.start()
        self._producer_thread.start()

    def stop(self):
        """Signals shutdown and joins threads."""
        self._stop_event.set()
        if self._producer_thread and self._producer_thread.is_alive():
            self._producer_thread.join(timeout=2.0)
        # Sentinel in case producer was blocked
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            pass
        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=2.0)

    def run(self):
        """Synchronously starts and waits for capture to finish or KeyboardInterrupt."""
        self.start()
        try:
            while not self._stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

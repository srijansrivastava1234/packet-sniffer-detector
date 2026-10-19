import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Generator


class AlertDatabase:
    def __init__(self, db_path: str = "alerts.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_mac TEXT,
                    target_ip TEXT,
                    target_port INTEGER,
                    description TEXT NOT NULL,
                    packet_hex TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_type ON security_alerts(attack_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_ip ON security_alerts(source_ip);")

    def log_alerts_batch(self, alerts: List[Dict[str, Any]]):
        """Batches multiple alerts in a single transaction to prevent disk thrashing."""
        if not alerts:
            return
        now_iso = datetime.now(timezone.utc).isoformat()
        records = [
            (
                a.get("timestamp", now_iso),
                a["attack_type"],
                a["source_ip"],
                a.get("source_mac"),
                a.get("target_ip"),
                a.get("target_port"),
                a["description"],
                a.get("packet_hex", ""),
            )
            for a in alerts
        ]
        with self._lock, self._get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO security_alerts (
                    timestamp, attack_type, source_ip, source_mac,
                    target_ip, target_port, description, packet_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                records,
            )

    def log_alert(
        self,
        attack_type: str,
        source_ip: str,
        description: str,
        packet_hex: str,
        source_mac: Optional[str] = None,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
    ):
        self.log_alerts_batch([{
            "attack_type": attack_type,
            "source_ip": source_ip,
            "description": description,
            "packet_hex": packet_hex,
            "source_mac": source_mac,
            "target_ip": target_ip,
            "target_port": target_port,
        }])

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

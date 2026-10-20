"""
Alert Manager: Records, deduplicates, persists to SQLite, and broadcasts security alerts.
"""
import sqlite3
import datetime
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from config.settings import DB_PATH

class AlertManager:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.listeners: List[Callable[[Dict[str, Any]], None]] = []
        # Cache recent alerts to prevent alert fatigue: (src_ip, attack_type) -> last_time
        self.recent_alerts: Dict[str, float] = {}
        self.dedup_window_seconds = 2.0
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        """Create alerts table if it doesn't already exist."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    attack_type TEXT NOT NULL,
                    signature_result TEXT,
                    ml_result TEXT,
                    risk_score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT
                )
            """)
            conn.commit()
            conn.close()

    def register_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback (e.g. WebSocket broadcaster) for new alerts."""
        self.listeners.append(callback)

    def create_alert(self,
                     source_ip: str,
                     destination_ip: str,
                     source_port: int,
                     destination_port: int,
                     protocol: str,
                     attack_type: str,
                     signature_result: str,
                     ml_result: str,
                     risk_score: float,
                     severity: str,
                     action: str,
                     details: str = "") -> Optional[Dict[str, Any]]:
        """Create and persist an alert if not deduplicated."""
        now_dt = datetime.datetime.now()
        timestamp_str = now_dt.isoformat()
        now_epoch = now_dt.timestamp()

        # Deduplication check
        dedup_key = f"{source_ip}:{attack_type}"
        if dedup_key in self.recent_alerts:
            if (now_epoch - self.recent_alerts[dedup_key]) < self.dedup_window_seconds:
                return None  # Suppress duplicate alert burst

        self.recent_alerts[dedup_key] = now_epoch

        alert_data = {
            "timestamp": timestamp_str,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "attack_type": attack_type,
            "signature_result": signature_result,
            "ml_result": ml_result,
            "risk_score": round(risk_score, 1),
            "severity": severity,
            "action": action,
            "details": details
        }

        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (
                    timestamp, source_ip, destination_ip, source_port, destination_port,
                    protocol, attack_type, signature_result, ml_result, risk_score,
                    severity, action, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp_str, source_ip, destination_ip, source_port, destination_port,
                protocol, attack_type, signature_result, ml_result, risk_score,
                severity, action, details
            ))
            alert_id = cursor.lastrowid
            conn.commit()
            conn.close()

        alert_data["id"] = alert_id

        # Dispatch to live listeners
        for listener in self.listeners:
            try:
                listener(alert_data)
            except Exception as e:
                print(f"[AlertManager] Listener error: {e}")

        return alert_data

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch latest alerts from SQLite."""
        with self._lock:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            alerts = [dict(row) for row in rows]
            conn.close()
        return alerts

    def get_alert_stats(self) -> Dict[str, Any]:
        """Summary counts of alerts by severity."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
            critical = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
            high = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'SUSPICIOUS'")
            suspicious = cursor.fetchone()[0]

            conn.close()

        return {
            "total_alerts": total,
            "critical_count": critical,
            "high_count": high,
            "suspicious_count": suspicious
        }

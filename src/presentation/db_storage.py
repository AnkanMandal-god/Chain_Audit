"""
Layer 3: SQLite Database Persistence Engine.

Stores and queries historical contract audits and live mempool anomaly alerts
for audit trail verification, historical risk analytics, and security reporting.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from config.settings import BASE_DIR

DB_PATH = BASE_DIR / "audit_history.db"


class AuditDatabase:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_db(self):
        """Initializes database schema and performance indexes if not already present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Smart contract audit records table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS contract_audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_address TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    summary TEXT,
                    security_findings TEXT,
                    actionable_recommendations TEXT,
                    detected_injections INTEGER DEFAULT 0,
                    audit_timestamp TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Mempool anomaly alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mempool_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_hash TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    target TEXT,
                    function_selector TEXT,
                    classification TEXT NOT NULL,
                    frequency_count INTEGER NOT NULL,
                    window_seconds REAL NOT NULL,
                    anomaly_reason TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Indexes for fast querying under high throughput
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_contract_audits_target
                ON contract_audits (target_address, risk_score);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_mempool_anomalies_sender
                ON mempool_anomalies (sender, detected_at);
            """)
            conn.commit()

    def save_contract_audit(self, report: Dict[str, Any]) -> int:
        """Saves a contract audit report into the database."""
        target_addr = str(report.get("target_address", "Unknown"))
        analysis_type = str(report.get("analysis_type", "SMART_CONTRACT_AUDIT"))
        risk_score = int(report.get("risk_score", 1))
        summary = str(report.get("summary", ""))
        findings_json = json.dumps(report.get("security_findings", []))
        rec_json = json.dumps(report.get("actionable_recommendations", []))
        telemetry = report.get("ingestion_telemetry", {})
        injections = int(telemetry.get("detected_injections", 0))
        timestamp = str(report.get("audit_timestamp", datetime.now(timezone.utc).isoformat()))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO contract_audits (
                    target_address, analysis_type, risk_score, summary,
                    security_findings, actionable_recommendations, detected_injections, audit_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (target_addr, analysis_type, risk_score, summary, findings_json, rec_json, injections, timestamp))
            conn.commit()
            return cursor.lastrowid

    def save_mempool_anomaly(self, tx_data: Dict[str, Any], anomaly_data: Dict[str, Any]) -> int:
        """Saves a flagged mempool anomaly into the database."""
        tx_hash = str(tx_data.get("tx_hash", "0x0"))
        sender = str(tx_data.get("sender", "0x0"))
        target = str(tx_data.get("target", "0x0"))
        selector = str(tx_data.get("function_selector") or "0x")
        classification = str(tx_data.get("payload_classification", "STANDARD_CALL"))
        count = int(anomaly_data.get("count_in_window", 1))
        window = float(anomaly_data.get("window_seconds", 10.0))
        reason = str(anomaly_data.get("anomaly_reason", "High frequency transaction burst"))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mempool_anomalies (
                    tx_hash, sender, target, function_selector, classification,
                    frequency_count, window_seconds, anomaly_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (tx_hash, sender, target, selector, classification, count, window, reason))
            conn.commit()
            return cursor.lastrowid

    def get_recent_audits(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves recent contract audits."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, target_address, risk_score, summary, detected_injections, audit_timestamp
                FROM contract_audits
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_recent_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves recent mempool anomaly alerts."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, tx_hash, sender, target, function_selector, classification, frequency_count, detected_at
                FROM mempool_anomalies
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_audits_paginated(self, page: int = 1, page_size: int = 10, search: str = "") -> Dict[str, Any]:
        """Retrieves paginated contract audits with total count for 'showing 1-10 of X' display."""
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        offset = (page - 1) * page_size

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if search.strip():
                query_term = f"%{search.strip()}%"
                cursor.execute("""
                    SELECT COUNT(*) FROM contract_audits
                    WHERE target_address LIKE ? OR summary LIKE ?
                """, (query_term, query_term))
                total = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT id, target_address, analysis_type, risk_score, summary, detected_injections, audit_timestamp, created_at
                    FROM contract_audits
                    WHERE target_address LIKE ? OR summary LIKE ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                """, (query_term, query_term, page_size, offset))
            else:
                cursor.execute("SELECT COUNT(*) FROM contract_audits")
                total = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT id, target_address, analysis_type, risk_score, summary, detected_injections, audit_timestamp, created_at
                    FROM contract_audits
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                """, (page_size, offset))

            rows = cursor.fetchall()
            items = [dict(row) for row in rows]
            total_pages = max(1, (total + page_size - 1) // page_size) if total > 0 else 1

            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "showing_from": (offset + 1) if total > 0 else 0,
                "showing_to": min(offset + page_size, total)
            }

    def get_anomalies_paginated(self, page: int = 1, page_size: int = 10, search: str = "") -> Dict[str, Any]:
        """Retrieves paginated mempool anomalies with total count for 'showing 1-10 of X' display."""
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        offset = (page - 1) * page_size

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if search.strip():
                query_term = f"%{search.strip()}%"
                cursor.execute("""
                    SELECT COUNT(*) FROM mempool_anomalies
                    WHERE tx_hash LIKE ? OR sender LIKE ? OR target LIKE ? OR classification LIKE ?
                """, (query_term, query_term, query_term, query_term))
                total = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT id, tx_hash, sender, target, function_selector, classification, frequency_count, window_seconds, anomaly_reason, detected_at
                    FROM mempool_anomalies
                    WHERE tx_hash LIKE ? OR sender LIKE ? OR target LIKE ? OR classification LIKE ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                """, (query_term, query_term, query_term, query_term, page_size, offset))
            else:
                cursor.execute("SELECT COUNT(*) FROM mempool_anomalies")
                total = cursor.fetchone()[0]

                cursor.execute("""
                    SELECT id, tx_hash, sender, target, function_selector, classification, frequency_count, window_seconds, anomaly_reason, detected_at
                    FROM mempool_anomalies
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                """, (page_size, offset))

            rows = cursor.fetchall()
            items = [dict(row) for row in rows]
            total_pages = max(1, (total + page_size - 1) // page_size) if total > 0 else 1

            return {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "showing_from": (offset + 1) if total > 0 else 0,
                "showing_to": min(offset + page_size, total)
            }

    def get_audit_by_id(self, audit_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves complete details of a single audit including parsed JSON fields."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM contract_audits WHERE id = ?", (audit_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            try:
                data["security_findings"] = json.loads(data["security_findings"]) if data.get("security_findings") else []
            except Exception:
                data["security_findings"] = []
            try:
                data["actionable_recommendations"] = json.loads(data["actionable_recommendations"]) if data.get("actionable_recommendations") else []
            except Exception:
                data["actionable_recommendations"] = []
            return data

    def get_anomaly_by_id(self, anomaly_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves details of a single mempool anomaly."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM mempool_anomalies WHERE id = ?", (anomaly_id,))
            row = cursor.fetchone()
            return dict(row) if row else None


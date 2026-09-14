"""
Layer 3: SQLite Database Persistence Engine.

Stores and queries historical contract audits and live mempool anomaly alerts
for audit trail verification, historical risk analytics, and security reporting.
"""
import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from config.settings import BASE_DIR

logger = logging.getLogger("ChainMind.Storage")
DB_PATH = BASE_DIR / "audit_history.db"


class AuditDatabase:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._init_db()
        try:
            self.cleanup_history(retention_days=30, max_records=1000)
        except Exception as e:
            logger.debug(f"Initial history cleanup: {e}")

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
                    detected_at TEXT NOT NULL
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

    def cleanup_old_routine_records(self, days: int = 7) -> int:
        """
        Deletes routine/safe mempool records (STANDARD_CALL, ETH_TRANSFER)
        that are older than 7 days. Flagged anomalies and security alerts are kept.
        """
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM mempool_anomalies
                WHERE classification IN ('STANDARD_CALL', 'ETH_TRANSFER')
                  AND (
                      detected_at < ?
                      OR detected_at < datetime('now', '-' || ? || ' days')
                  )
            """, (cutoff_iso, days))
            deleted = cursor.rowcount
            conn.commit()
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} safe/routine mempool records older than {days} days.")
            return deleted

    def cleanup_history(self, retention_days: int = 30, max_records: int = 1000) -> int:
        """
        Retain high-value security history while pruning stale, low-priority records.

        Priority is severity first and recency second. Critical/high-risk audits and
        anomalies are retained; routine records are eligible for time-based cleanup.
        If a table still exceeds the configured cap, the lowest priority records are
        deleted first.
        """
        retention_days = max(1, int(retention_days))
        max_records = max(50, int(max_records))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        deleted = 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM mempool_anomalies
                WHERE detected_at < ?
                  AND classification IN (
                    'STANDARD_CALL', 'ETH_TRANSFER', 'ELEVATED_ACTIVITY',
                    'HIGH_GAS_SPIKE', 'LARGE_VALUE_TRANSFER'
                  )
            """, (cutoff,))
            deleted += max(0, cursor.rowcount)

            cursor.execute("""
                DELETE FROM contract_audits
                WHERE audit_timestamp < ? AND risk_score < 7
            """, (cutoff,))
            deleted += max(0, cursor.rowcount)

            for table, timestamp_col, priority_sql in (
                ("mempool_anomalies", "detected_at",
                 "CASE WHEN classification IN ('MEV_SANDWICH_ATTACK','SUSPICIOUS_HIGH_RISK_CALL','HIGH_FREQUENCY_BURST') THEN 3 "
                 "WHEN classification IN ('PROXY_UPGRADE','INFINITE_APPROVAL') THEN 2 ELSE 1 END"),
                ("contract_audits", "audit_timestamp",
                 "CASE WHEN risk_score >= 7 THEN 3 WHEN risk_score >= 4 THEN 2 ELSE 1 END"),
            ):
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                total = cursor.fetchone()[0]
                excess = total - max_records
                if excess > 0:
                    cursor.execute(f"""
                        DELETE FROM {table}
                        WHERE id IN (
                            SELECT id FROM {table}
                            ORDER BY {priority_sql} ASC, {timestamp_col} ASC
                            LIMIT ?
                        )
                    """, (excess,))
                    deleted += max(0, cursor.rowcount)
            conn.commit()
        if deleted:
            logger.info("History retention removed %s low-priority records.", deleted)
        return deleted

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
        """Saves a mempool transaction or anomaly with an ISO-8601 UTC timestamp."""
        tx_hash = str(tx_data.get("tx_hash") or tx_data.get("hash") or "0x0")
        sender = str(tx_data.get("sender") or tx_data.get("from") or "0x0")
        target = str(tx_data.get("target") or tx_data.get("to") or "0x0")
        selector = str(tx_data.get("function_selector") or "0x")
        classification = str(tx_data.get("classification") or tx_data.get("payload_classification") or "STANDARD_CALL")
        count = int(anomaly_data.get("count_in_window", 1))
        window = float(anomaly_data.get("window_seconds", 10.0))
        reason = str(anomaly_data.get("anomaly_reason") or tx_data.get("anomaly_reason") or "Elevated mempool transaction activity")
        detected_at = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mempool_anomalies (
                    tx_hash, sender, target, function_selector, classification,
                    frequency_count, window_seconds, anomaly_reason, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tx_hash, sender, target, selector, classification, count, window, reason, detected_at))
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

    def get_audits_paginated(self, page: int = 1, page_size: int = 10, search: str = "",
                              risk_min: int = 0, risk_max: int = 10, sort_order: str = "desc") -> Dict[str, Any]:
        """Retrieves paginated contract audits with risk level and sort filtering."""
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        offset = (page - 1) * page_size
        order = "ASC" if sort_order == "asc" else "DESC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            conditions = ["risk_score >= ?", "risk_score <= ?"]
            params: list = [risk_min, risk_max]

            if search.strip():
                conditions.append("(target_address LIKE ? OR summary LIKE ?)")
                query_term = f"%{search.strip()}%"
                params.extend([query_term, query_term])

            where_clause = "WHERE " + " AND ".join(conditions)

            cursor.execute(f"SELECT COUNT(*) FROM contract_audits {where_clause}", params)
            total = cursor.fetchone()[0]

            cursor.execute(f"""
                SELECT id, target_address, analysis_type, risk_score, summary, detected_injections, audit_timestamp, created_at
                FROM contract_audits {where_clause}
                ORDER BY id {order}
                LIMIT ? OFFSET ?
            """, params + [page_size, offset])

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

    def get_anomalies_paginated(self, page: int = 1, page_size: int = 10, search: str = "",
                                 classification: str = "", sort_order: str = "desc") -> Dict[str, Any]:
        """Retrieves paginated mempool anomalies with classification and sort filtering."""
        try:
            self.cleanup_history(retention_days=30, max_records=1000)
        except Exception as e:
            logger.debug(f"Routine retention cleanup error: {e}")

        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        offset = (page - 1) * page_size
        order = "ASC" if sort_order == "asc" else "DESC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            conditions: list = []
            params: list = []

            if search.strip():
                conditions.append("(tx_hash LIKE ? OR sender LIKE ? OR target LIKE ? OR classification LIKE ?)")
                query_term = f"%{search.strip()}%"
                params.extend([query_term, query_term, query_term, query_term])

            if classification and classification.strip():
                conditions.append("classification LIKE ?")
                params.append(f"%{classification.strip()}%")

            where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

            cursor.execute(f"SELECT COUNT(*) FROM mempool_anomalies {where_clause}", params)
            total = cursor.fetchone()[0]

            cursor.execute(f"""
                SELECT id, tx_hash, sender, target, function_selector, classification, frequency_count, window_seconds, anomaly_reason, detected_at
                FROM mempool_anomalies {where_clause}
                ORDER BY id {order}
                LIMIT ? OFFSET ?
            """, params + [page_size, offset])

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


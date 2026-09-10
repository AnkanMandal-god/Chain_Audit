"""Unit tests for SQLite AuditDatabase persistence."""
import pytest
from pathlib import Path
from src.presentation.db_storage import AuditDatabase


def test_sqlite_contract_audit_persistence(tmp_path):
    test_db = tmp_path / "test_audit.db"
    db = AuditDatabase(db_path=test_db)

    audit_payload = {
        "target_address": "0x1111222233334444555566667777888899990000",
        "analysis_type": "SMART_CONTRACT_AUDIT",
        "risk_score": 8,
        "summary": "Reentrancy detected",
        "security_findings": [{"severity": "CRITICAL", "category": "Reentrancy", "location": "withdraw()", "description": "state after call"}],
        "actionable_recommendations": ["Use ReentrancyGuard"],
        "ingestion_telemetry": {"detected_injections": 1},
        "audit_timestamp": "2026-09-10T12:00:00Z"
    }

    row_id = db.save_contract_audit(audit_payload)
    assert row_id is not None
    assert row_id > 0

    recent = db.get_recent_audits(limit=5)
    assert len(recent) == 1
    assert recent[0]["target_address"] == "0x1111222233334444555566667777888899990000"
    assert recent[0]["risk_score"] == 8
    assert recent[0]["detected_injections"] == 1


def test_sqlite_mempool_anomaly_persistence(tmp_path):
    test_db = tmp_path / "test_audit.db"
    db = AuditDatabase(db_path=test_db)

    tx_data = {
        "tx_hash": "0xdeadbeef1234",
        "sender": "0xbot001",
        "target": "0xdex001",
        "function_selector": "0x54f3d9b4",
        "payload_classification": "SUSPICIOUS_HIGH_RISK_CALL"
    }
    anomaly_data = {
        "count_in_window": 8,
        "window_seconds": 10.0,
        "anomaly_reason": "High frequency burst: 8 txs in 10s"
    }

    row_id = db.save_mempool_anomaly(tx_data, anomaly_data)
    assert row_id is not None
    assert row_id > 0

    recent = db.get_recent_anomalies(limit=5)
    assert len(recent) == 1
    assert recent[0]["tx_hash"] == "0xdeadbeef1234"
    assert recent[0]["frequency_count"] == 8
    assert recent[0]["classification"] == "SUSPICIOUS_HIGH_RISK_CALL"

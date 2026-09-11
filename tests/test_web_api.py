"""
Unit tests for Chain-Mind Web API and Contract Relationship Discovery Engine.
"""
import pytest
from fastapi.testclient import TestClient
from src.web.server import app
from src.web.dependency_detector import ContractRelationshipDetector

client = TestClient(app)

def test_web_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ONLINE"
    assert "credentials_matrix" in data
    assert len(data["credentials_matrix"]) >= 4

def test_web_demo_samples():
    response = client.get("/api/demo/samples")
    assert response.status_code == 200
    data = response.json()
    assert "single_samples" in data
    assert len(data["single_samples"]) >= 2
    assert "sample_suite" in data

def test_contract_relationship_detector():
    source_vault = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    import "./Ownable.sol";
    import "./IERC20.sol";
    contract Vault is Ownable {
        IERC20 public token;
    }
    """
    analysis = ContractRelationshipDetector.analyze_source(source_vault, file_identifier="Vault.sol")
    assert "Vault" in [c["name"] for c in analysis["contracts"]]
    assert "Ownable" in analysis["contracts"][0]["parents"]
    assert "./Ownable.sol" in analysis["imports"]

    files_map = {
        "Vault.sol": analysis,
        "Ownable.sol": ContractRelationshipDetector.analyze_source("contract Ownable {}", "Ownable.sol")
    }
    graph = ContractRelationshipDetector.build_dependency_graph(files_map, target_file="Vault.sol")
    assert len(graph["nodes"]) >= 2
    assert len(graph["edges"]) >= 1

def test_history_paginated_api():
    # Test audits pagination
    res_audits = client.get("/api/history/audits?page=1&page_size=5")
    assert res_audits.status_code == 200
    data_audits = res_audits.json()
    assert "showing_from" in data_audits
    assert "showing_to" in data_audits
    assert "total" in data_audits

    # Test anomalies pagination
    res_anomalies = client.get("/api/history/anomalies?page=1&page_size=5")
    assert res_anomalies.status_code == 200
    data_anomalies = res_anomalies.json()
    assert "showing_from" in data_anomalies
    assert "total" in data_anomalies

def test_settings_auth_verification():
    # Invalid passcode should always fail
    bad_res = client.post("/api/settings/verify-auth", json={"passcode": "wrong-password-xyz"})
    assert bad_res.status_code == 401

    # Read actual passcode from config (may have been changed from default)
    from src.web.server import load_web_settings
    cfg = load_web_settings()
    actual_passcode = cfg.get("admin_passcode", "chainmind-admin")
    good_res = client.post("/api/settings/verify-auth", json={"passcode": actual_passcode})
    assert good_res.status_code == 200
    assert good_res.json()["authenticated"] is True

def test_audit_single_contract_api():
    sol_code = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract SimpleSafe {
        uint256 public value;
        function set(uint256 v) external {
            value = v;
        }
    }
    """
    res = client.post("/api/audit/contract", json={"source_code": sol_code, "target_path": "SimpleSafe.sol"})
    # 200 = audit succeeded, 400 = strict mode requires missing Gemini key (acceptable)
    assert res.status_code in (200, 400)
    if res.status_code == 200:
        data = res.json()
        assert data.get("status") == "SUCCESS" or data.get("security_status") in ["SAFE", "WARNING", "CRITICAL"]
        assert "risk_score" in data

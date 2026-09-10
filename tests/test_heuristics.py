"""Unit tests for expanded heuristic vulnerability rules in LLMAuditor."""
from src.processing.llm_auditor import LLMAuditor

auditor = LLMAuditor()


def test_unprotected_initialize_heuristic():
    code = '''
    contract LogicV1 {
        address public owner;
        function initialize(address _owner) public {
            owner = _owner;
        }
    }
    '''
    res = auditor.heuristic_audit_contract(code, "0x123", "LogicV1")
    categories = [f["category"] for f in res["security_findings"]]
    assert "Unprotected Initializer" in categories
    assert res["risk_score"] >= 8


def test_missing_zero_address_validation():
    code = '''
    contract Treasury {
        address public owner;
        function setOwner(address newOwner) external {
            owner = newOwner;
        }
    }
    '''
    res = auditor.heuristic_audit_contract(code, "0x456", "Treasury")
    categories = [f["category"] for f in res["security_findings"]]
    assert "Missing Zero-Address Validation" in categories


def test_timestamp_dependence():
    code = '''
    contract Lottery {
        function pickWinner() external {
            require(block.timestamp % 2 == 0, "Not lucky");
        }
    }
    '''
    res = auditor.heuristic_audit_contract(code, "0x789", "Lottery")
    categories = [f["category"] for f in res["security_findings"]]
    assert "Timestamp Dependence" in categories


def test_pre_080_overflow_detection():
    code = '''
    pragma solidity ^0.7.6;
    contract LegacyVault {
        mapping(address => uint256) public balances;
        function addBalance(uint256 amount) external {
            balances[msg.sender] += amount;
        }
    }
    '''
    res = auditor.heuristic_audit_contract(code, "0xaaa", "LegacyVault")
    categories = [f["category"] for f in res["security_findings"]]
    assert "Integer Overflow/Underflow" in categories

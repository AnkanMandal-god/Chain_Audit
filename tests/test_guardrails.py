"""Unit tests for Layer 2: Guardrails and Self-Healing JSON Repair."""
import json
from src.processing.guardrails import GuardrailEngine, Layer1Payload, Layer2AuditOutput


def test_repair_json_with_markdown_fences():
    raw_llm = '''
    ```json
    {
      "status": "SUCCESS",
      "risk_score": 8,
      "summary": "Vulnerable contract",
    }
    ```
    '''
    repaired = GuardrailEngine.repair_json_string(raw_llm)
    assert repaired is not None
    assert repaired["status"] == "SUCCESS"
    assert repaired["risk_score"] == 8


def test_repair_json_with_conversational_fluff():
    raw_llm = '''
    Sure! Here is your audit JSON:
    {
      "status": "SUCCESS",
      "risk_score": 3,
      "summary": "Safe contract"
    }
    Hope this helps!
    '''
    repaired = GuardrailEngine.repair_json_string(raw_llm)
    assert repaired is not None
    assert repaired["status"] == "SUCCESS"
    assert repaired["risk_score"] == 3


def test_layer1_validation():
    valid_data = {
        "status": "SUCCESS",
        "ingestion_metadata": {
            "source_type": "CONTRACT_SOURCE_CODE",
            "timestamp_processed": "2026-09-10T12:00:00Z",
            "input_size_bytes": 120,
            "sanitization_performed": True
        },
        "extracted_data": {
            "target_address": "0x1234567890123456789012345678901234567890",
            "contract_metadata": {
                "primary_contract_name": "Vault",
                "compiler_version": "^0.8.0",
                "imports_count": 0
            },
            "function_selector": None,
            "cleaned_payload": "contract Vault {}",
            "structural_summary": {
                "state_changing_functions": ["withdraw()"],
                "has_raw_assembly": False,
                "detected_prompt_injection_attempts": 0
            }
        },
        "pipeline_routing": {
            "recommended_downstream_engine": "LLM_SECURITY_AUDITOR"
        }
    }
    is_valid, validated, err = GuardrailEngine.validate_layer1(valid_data)
    assert is_valid
    assert validated.status == "SUCCESS"
    assert err is None


def test_repair_json_with_python_literals():
    # Tests conversion of True, False, None to valid JSON
    raw_llm = '''
    {
      "status": "SUCCESS",
      "risk_score": 5,
      "has_raw_assembly": False,
      "is_verified": True,
      "secondary_error": None
    }
    '''
    repaired = GuardrailEngine.repair_json_string(raw_llm)
    assert repaired is not None
    assert repaired["has_raw_assembly"] is False
    assert repaired["is_verified"] is True
    assert repaired["secondary_error"] is None


def test_repair_json_with_single_quotes():
    # Tests conversion of single-quoted keys and string values
    raw_llm = '''
    {
      'status': 'SUCCESS',
      'risk_score': 7,
      'summary': 'Vulnerable proxy pattern'
    }
    '''
    repaired = GuardrailEngine.repair_json_string(raw_llm)
    assert repaired is not None
    assert repaired["status"] == "SUCCESS"
    assert repaired["risk_score"] == 7
    assert repaired["summary"] == "Vulnerable proxy pattern"


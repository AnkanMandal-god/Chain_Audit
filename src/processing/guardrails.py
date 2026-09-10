"""
Layer 2: Validation & Security Guardrails.

Enforces strict JSON schema validation via Pydantic and provides
self-healing JSON repair for LLM outputs (stripping markdown backticks,
fixing missing brackets, and isolating JSON substrings).
"""
import re
import json
import logging
from typing import List, Optional, Literal, Dict, Any, Tuple
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)


# ----------------- Layer 1 Schemas -----------------

class IngestionMetadata(BaseModel):
    source_type: Literal["CONTRACT_SOURCE_CODE", "MEMPOOL_TRANSACTION"]
    timestamp_processed: str
    input_size_bytes: int
    sanitization_performed: bool


class ContractMetadata(BaseModel):
    primary_contract_name: Optional[str] = None
    compiler_version: Optional[str] = None
    imports_count: int = 0


class StructuralSummary(BaseModel):
    state_changing_functions: List[str] = Field(default_factory=list)
    has_raw_assembly: bool = False
    detected_prompt_injection_attempts: int = 0


class Layer1ExtractedData(BaseModel):
    target_address: Optional[str] = None
    contract_metadata: ContractMetadata
    function_selector: Optional[str] = None
    cleaned_payload: str
    structural_summary: StructuralSummary


class Layer1PipelineRouting(BaseModel):
    recommended_downstream_engine: Literal["LLM_SECURITY_AUDITOR", "ALGORITHMIC_PATTERN_MATCHER"]


class Layer1Payload(BaseModel):
    status: Literal["SUCCESS", "FAILED"]
    ingestion_metadata: IngestionMetadata
    extracted_data: Layer1ExtractedData
    pipeline_routing: Layer1PipelineRouting


# ----------------- Layer 2 Schemas -----------------

class SecurityFinding(BaseModel):
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: str
    description: str
    location: str


class AnomalyFlag(BaseModel):
    status: Literal["NORMAL", "ANOMALOUS"]
    reason: str


class Layer2AuditOutput(BaseModel):
    status: Literal["SUCCESS", "ERROR"]
    audit_timestamp: str
    target_address: str
    analysis_type: Literal["SMART_CONTRACT_AUDIT", "MEMPOOL_TRANSACTION_AUDIT"]
    risk_score: int = Field(ge=1, le=10)
    summary: str
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    anomaly_flag: AnomalyFlag
    actionable_recommendations: List[str] = Field(default_factory=list)


class GuardrailEngine:
    @classmethod
    def repair_json_string(cls, raw_text: str) -> Optional[Dict[str, Any]]:
        """
        Self-healing JSON repair pipeline:
        1. Strips Markdown code fences (```json ... ```)
        2. Isolates outermost JSON dictionary { ... }
        3. Converts Pythonic literals (True/False/None) to valid JSON (true/false/null)
        4. Normalizes single-quoted keys and strings
        5. Removes invalid trailing commas before } or ]
        """
        text = raw_text.strip()

        # 1. Remove markdown fences
        if "```" in text:
            match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
            if match:
                text = match.group(1).strip()

        # 2. Extract curly braces block
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx + 1]

        # 3. Convert Python literals to JSON
        text = re.sub(r'\bTrue\b', 'true', text)
        text = re.sub(r'\bFalse\b', 'false', text)
        text = re.sub(r'\bNone\b', 'null', text)

        # 4. Remove trailing commas before } or ]
        text = re.sub(r',\s*([}\]])', r'\1', text)

        # Try parsing first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 5. Fix single quotes around keys and values: 'key': 'val' -> "key": "val"
        try:
            # Replace single quotes around word keys: 'name': -> "name":
            single_quote_fixed = re.sub(r"'([a-zA-Z0-9_]+)'\s*:", r'"\1":', text)
            # Replace single quotes around string values: : 'value' -> : "value"
            single_quote_fixed = re.sub(r":\s*'([^']*)'", r': "\1"', single_quote_fixed)
            return json.loads(single_quote_fixed)
        except json.JSONDecodeError as err:
            logger.error(f"Failed to parse repaired JSON: {err}")
            return None

    @classmethod
    def validate_layer1(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[Layer1Payload], Optional[str]]:
        try:
            validated = Layer1Payload.model_validate(data)
            return True, validated, None
        except ValidationError as e:
            return False, None, str(e)

    @classmethod
    def validate_layer2(cls, data: Dict[str, Any]) -> Tuple[bool, Optional[Layer2AuditOutput], Optional[str]]:
        try:
            validated = Layer2AuditOutput.model_validate(data)
            return True, validated, None
        except ValidationError as e:
            return False, None, str(e)

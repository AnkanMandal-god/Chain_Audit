"""
Chain-Mind Auditor: Unified Pipeline Orchestrator.

Ties Layer 1 (Ingestion & Sanitization) -> Layer 2 (DSA & LLM Processing) -> Layer 3 (Presentation)
into a cohesive asynchronous workflow.
"""
import asyncio
import logging
from typing import Dict, Any, Optional

from src.ingestion.normalizer import Normalizer
from src.ingestion.etherscan_client import EtherscanClient
from src.ingestion.mempool_listener import MempoolListener, SimulatedMempoolStream
from src.ingestion.buffer_queue import IngestionBufferQueue

from src.processing.hex_engine import HexEngine
from src.processing.sliding_window import SlidingWindowRateTracker
from src.processing.sandwich_detector import SandwichDetector
from src.processing.llm_auditor import LLMAuditor
from src.processing.guardrails import GuardrailEngine

from src.presentation.cli_formatter import CLIFormatter
from src.presentation.json_exporter import JSONExporter
from src.presentation.db_storage import AuditDatabase

logger = logging.getLogger(__name__)


class ChainMindPipeline:
    def __init__(
        self,
        etherscan_api_key: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        chain: str = "ethereum",
        sliding_window_sec: float = 10.0,
        anomaly_threshold: int = 5,
        strict_mode: bool = False
    ):
        self.chain = chain
        self.strict_mode = strict_mode
        self.etherscan_client = EtherscanClient(api_key=etherscan_api_key, chain=chain)
        self.llm_auditor = LLMAuditor(api_key=gemini_api_key, strict_mode=strict_mode)
        self.rate_tracker = SlidingWindowRateTracker(
            window_seconds=sliding_window_sec,
            threshold_count=anomaly_threshold
        )
        self.sandwich_detector = SandwichDetector(window_seconds=5.0)
        self.buffer_queue = IngestionBufferQueue(maxsize=1000)
        self.db = AuditDatabase()

    async def audit_smart_contract_source(
        self,
        raw_source: str,
        target_address: str = "0x0000000000000000000000000000000000000000",
        raw_json_output: bool = False
    ) -> Dict[str, Any]:
        """
        Executes end-to-end pipeline for smart contract source code:
        1. Layer 1 Ingestion: Unpack multi-file JSON, strip comments, neutralize prompt injections, extract metadata.
        2. Validate Layer 1 schema via Guardrails.
        3. Layer 2 Processing: Context isolation with XML tags, LLM / Heuristic security audit.
        4. Validate Layer 2 schema via Guardrails.
        5. Layer 3 Presentation: Color-coded CLI terminal report or raw JSON.
        """
        # --- LAYER 1: Ingestion & Preprocessing ---
        layer1_payload = Normalizer.process_contract_source(raw_source, target_address=target_address)
        is_valid_l1, _, err_l1 = GuardrailEngine.validate_layer1(layer1_payload)
        if not is_valid_l1:
            logger.warning(f"Layer 1 schema validation warning: {err_l1}")

        cleaned_code = layer1_payload["extracted_data"]["cleaned_payload"]
        contract_name = layer1_payload["extracted_data"]["contract_metadata"]["primary_contract_name"]

        # --- LAYER 2: Core Processing & Security Engine ---
        audit_result = await self.llm_auditor.audit_contract(
            cleaned_source=cleaned_code,
            target_address=target_address,
            contract_name=contract_name
        )

        # Guardrail check & repair
        is_valid_l2, validated_l2, err_l2 = GuardrailEngine.validate_layer2(audit_result)
        if not is_valid_l2:
            if self.strict_mode:
                raise ValueError(f"Strict Mode Validation Error: Layer 2 LLM output failed schema check: {err_l2}")
            repaired = GuardrailEngine.repair_json_string(str(audit_result))
            if repaired:
                audit_result = repaired

        # Include ingestion telemetry
        audit_result["ingestion_telemetry"] = {
            "source_type": layer1_payload["ingestion_metadata"]["source_type"],
            "input_size_bytes": layer1_payload["ingestion_metadata"]["input_size_bytes"],
            "sanitization_performed": True,
            "detected_injections": layer1_payload["extracted_data"]["structural_summary"]["detected_prompt_injection_attempts"],
            "state_changing_functions": layer1_payload["extracted_data"]["structural_summary"]["state_changing_functions"],
            "has_raw_assembly": layer1_payload["extracted_data"]["structural_summary"]["has_raw_assembly"]
        }

        # Save to SQLite Audit Database
        try:
            self.db.save_contract_audit(audit_result)
        except Exception as db_err:
            logger.warning(f"Failed to persist contract audit to database: {db_err}")

        # --- LAYER 3: Output & Presentation ---
        if raw_json_output:
            JSONExporter.print_json(audit_result)
        else:
            CLIFormatter.display_contract_audit_report(audit_result)

        return audit_result

    async def audit_etherscan_contract(
        self,
        address: str,
        raw_json_output: bool = False
    ) -> Dict[str, Any]:
        """Fetches from Etherscan API and runs full audit."""
        fetch_res = await self.etherscan_client.get_contract_source_code(address)
        if not fetch_res.get("success"):
            error_report = {
                "status": "ERROR",
                "target_address": address,
                "error": fetch_res.get("error", "Failed to fetch source from Etherscan.")
            }
            if raw_json_output:
                JSONExporter.print_json(error_report)
            else:
                from rich.console import Console
                Console().print(f"[bold red]Etherscan Ingestion Error:[/bold red] {error_report['error']}")
            return error_report

        return await self.audit_smart_contract_source(
            raw_source=fetch_res["source_code"],
            target_address=address,
            raw_json_output=raw_json_output
        )

    async def process_single_mempool_tx(
        self,
        tx: Dict[str, Any],
        render_cli: bool = True
    ) -> Dict[str, Any]:
        """
        Processes a single mempool transaction:
        1. Layer 1 Ingestion: Normalize hex, extract selector.
        2. Layer 2 Processing: HexEngine calldata classification + Sliding Window frequency tracking.
        3. Layer 3 Presentation: Color-coded terminal alert or structured dict.
        """
        # Layer 1
        l1_payload = Normalizer.process_mempool_transaction(tx)

        # Layer 2: Hex engine parsing
        parsed_hex = HexEngine.parse_transaction(tx)

        # Layer 2: Sliding window frequency counter (DSA)
        sender = parsed_hex["sender"]
        timestamp = tx.get("timestamp")
        is_anomalous, count, window_meta = self.rate_tracker.record_transaction(sender, timestamp=timestamp)

        # Check for MEV Sandwich Attack
        is_sandwich, sandwich_meta = self.sandwich_detector.record_and_evaluate(parsed_hex, timestamp=timestamp)
        if is_sandwich:
            try:
                self.db.save_mempool_anomaly({
                    "tx_hash": sandwich_meta["backrun_tx"],
                    "sender": sandwich_meta["attacker_address"],
                    "target": sandwich_meta["target_pool"],
                    "function_selector": parsed_hex.get("function_selector"),
                    "payload_classification": "MEV_SANDWICH_ATTACK"
                }, {
                    "count_in_window": 3,
                    "window_seconds": self.sandwich_detector.window_seconds,
                    "anomaly_reason": sandwich_meta["detection_reason"]
                })
            except Exception as db_err:
                logger.warning(f"Failed to persist sandwich attack: {db_err}")

        # Persist anomaly if flagged or critical call
        if is_anomalous or parsed_hex.get("payload_classification") == "SUSPICIOUS_HIGH_RISK_CALL":
            try:
                self.db.save_mempool_anomaly(parsed_hex, window_meta)
            except Exception as db_err:
                logger.warning(f"Failed to persist mempool anomaly to database: {db_err}")

        combined_result = {
            "status": "SUCCESS",
            "layer1": l1_payload,
            "hex_analysis": parsed_hex,
            "frequency_anomaly": window_meta,
            "sandwich_attack": sandwich_meta
        }

        if render_cli:
            CLIFormatter.display_mempool_tx_alert(parsed_hex, window_meta)
            if is_sandwich:
                from rich.console import Console
                Console(safe_box=True).print(f"[bold red on black] [MEV SANDWICH DETECTED] [/bold red on black] Attacker: {sandwich_meta['attacker_address'][:10]}... | Target Pool: {sandwich_meta['target_pool'][:10]}... | Victim: {sandwich_meta['victim_sender'][:10]}...")

        return combined_result

    async def stream_mempool(
        self,
        simulate: bool = True,
        count: int = 25,
        interval: float = 0.2
    ):
        """Streams mempool transactions through the pipeline."""
        if simulate:
            stream = SimulatedMempoolStream.stream_synthetic(count=count, interval=interval, simulate_burst=True)
        else:
            from config.settings import settings
            chain_cfg = settings.get_chain_config(self.chain) if self.chain in settings.chains else None
            ws_url = chain_cfg["ws_rpc"] if chain_cfg else None
            http_rpc = chain_cfg["http_rpc"] if chain_cfg else None
            listener = MempoolListener(ws_url=ws_url, http_rpc_url=http_rpc)
            stream = listener.listen_live()

        processed = 0
        async for tx in stream:
            if tx.get("_error"):
                raise ConnectionError(f"{tx.get('error')} — {tx.get('details')}")
            await self.process_single_mempool_tx(tx, render_cli=True)
            processed += 1
            if count > 0 and processed >= count:
                break

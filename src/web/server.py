"""
Chain-Mind Auditor: Web API Backend & WebSocket Streaming Server.
Provides REST endpoints and real-time WebSocket feeds for the Web Operations Center.
"""
import os
import sys
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from config.settings import settings, BASE_DIR
from src.pipeline import ChainMindPipeline
from src.presentation.db_storage import AuditDatabase
from src.presentation.html_reporter import HTMLReporter
from src.presentation.sarif_exporter import SARIFExporter
from src.presentation.remediation_engine import RemediationEngine
from src.ingestion.mempool_listener import SimulatedMempoolStream, MempoolListener
from src.ingestion.normalizer import Normalizer
from src.processing.hex_engine import HexEngine
from src.processing.sliding_window import SlidingWindowRateTracker
from src.processing.sandwich_detector import SandwichDetector
from src.web.dependency_detector import ContractRelationshipDetector

logger = logging.getLogger("chainmind.web")

# Paths
CONFIG_FILE = Path("/tmp/web_settings.json") if os.getenv("VERCEL") else (BASE_DIR / "config" / "web_settings.json")
STATIC_DIR = BASE_DIR / "src" / "web" / "static"

app = FastAPI(
    title="Chain-Mind Auditor API",
    version="2.0.0",
    description="End-to-End Blockchain Security Ingestion & Auditing Engine"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = AuditDatabase()

# Global config helper
def load_web_settings() -> Dict[str, Any]:
    default_settings = {
        "admin_passcode": os.getenv("CHAINMIND_ADMIN_PASSCODE", "chainmind-admin"),
        "gemini_api_key": settings.gemini_api_key or "",
        "etherscan_api_key": settings.etherscan_api_key or "",
        "arbiscan_api_key": os.getenv("ARBISCAN_API_KEY", ""),
        "polygonscan_api_key": os.getenv("POLYGONSCAN_API_KEY", ""),
        "basescan_api_key": os.getenv("BASESCAN_API_KEY", ""),
        "optimistic_api_key": os.getenv("OPTIMISTIC_API_KEY", ""),
        "eth_rpc_ws_url": settings.eth_rpc_ws_url,
        "eth_rpc_http_url": settings.eth_rpc_http_url,
        "default_chain": "ethereum",
        "strict_mode": False,
        "sliding_window_seconds": settings.sliding_window_seconds,
        "anomaly_tx_threshold": settings.anomaly_tx_threshold,
        "enable_heuristic_engine": True,
        "enable_llm_engine": True,
        "enable_selector_analysis": True,
        "enable_frequency_analysis": True,
        "enable_sandwich_detection": True,
        "enable_prompt_neutralization": True,
        "history_retention_days": 30,
        "history_max_records": 1000,
    }
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                default_settings.update(saved)
        except Exception as e:
            logger.warning(f"Could not read web_settings.json: {e}")
    return default_settings

def save_web_settings(new_settings: Dict[str, Any]):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(new_settings, f, indent=2)
    # Apply to in-memory settings
    settings.gemini_api_key = new_settings.get("gemini_api_key", "")
    settings.etherscan_api_key = new_settings.get("etherscan_api_key", "")
    settings.eth_rpc_ws_url = new_settings.get("eth_rpc_ws_url", settings.eth_rpc_ws_url)
    settings.eth_rpc_http_url = new_settings.get("eth_rpc_http_url", settings.eth_rpc_http_url)
    settings.sliding_window_seconds = float(new_settings.get("sliding_window_seconds", 10.0))
    settings.anomaly_tx_threshold = int(new_settings.get("anomaly_tx_threshold", 5))


SECRET_SETTING_KEYS = {
    "admin_passcode",
    "gemini_api_key",
    "etherscan_api_key",
    "arbiscan_api_key",
    "polygonscan_api_key",
    "basescan_api_key",
    "optimistic_api_key",
}


def mask_secret(value: Any) -> str:
    """Return a non-reversible display value; secrets never leave the server."""
    if not value:
        return ""
    return "••••••••" + str(value)[-4:]


def public_settings(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Expose editable settings without returning credential material."""
    return {
        "gemini_api_key": mask_secret(cfg.get("gemini_api_key")),
        "etherscan_api_key": mask_secret(cfg.get("etherscan_api_key")),
        "arbiscan_api_key": mask_secret(cfg.get("arbiscan_api_key")),
        "polygonscan_api_key": mask_secret(cfg.get("polygonscan_api_key")),
        "basescan_api_key": mask_secret(cfg.get("basescan_api_key")),
        "optimistic_api_key": mask_secret(cfg.get("optimistic_api_key")),
        "configured_secrets": {
            key: bool(cfg.get(key))
            for key in SECRET_SETTING_KEYS
            if key != "admin_passcode"
        },
        "eth_rpc_ws_url": cfg.get("eth_rpc_ws_url", ""),
        "eth_rpc_http_url": cfg.get("eth_rpc_http_url", ""),
        "default_chain": cfg.get("default_chain", "ethereum"),
        "strict_mode": bool(cfg.get("strict_mode", False)),
        "sliding_window_seconds": cfg.get("sliding_window_seconds", 10.0),
        "anomaly_tx_threshold": cfg.get("anomaly_tx_threshold", 5),
        "enable_heuristic_engine": bool(cfg.get("enable_heuristic_engine", True)),
        "enable_llm_engine": bool(cfg.get("enable_llm_engine", True)),
        "enable_selector_analysis": bool(cfg.get("enable_selector_analysis", True)),
        "enable_frequency_analysis": bool(cfg.get("enable_frequency_analysis", True)),
        "enable_sandwich_detection": bool(cfg.get("enable_sandwich_detection", True)),
        "enable_prompt_neutralization": bool(cfg.get("enable_prompt_neutralization", True)),
        "history_retention_days": int(cfg.get("history_retention_days", 30)),
        "history_max_records": int(cfg.get("history_max_records", 1000)),
    }

# Ensure initial config exists
current_cfg = load_web_settings()
save_web_settings(current_cfg)


# -------------------------------------------------------------
# Request & Response Models
# -------------------------------------------------------------

class AuditContractRequest(BaseModel):
    source_code: Optional[str] = None
    target_path: Optional[str] = None
    contract_address: Optional[str] = None
    chain: str = "ethereum"
    strict_mode: Optional[bool] = None

class BatchAuditRequest(BaseModel):
    contracts: List[Dict[str, str]]  # [{"name": "Vault.sol", "source": "..."}]
    chain: str = "ethereum"
    strict_mode: Optional[bool] = None

class AuthVerifyRequest(BaseModel):
    passcode: str

class UpdateSettingsRequest(BaseModel):
    passcode: str
    settings: Dict[str, Any]

class RefineContractRequest(BaseModel):
    source_code: str
    findings: List[Dict[str, Any]]
    target_address: str = "Contract.sol"


# -------------------------------------------------------------
# Credentials Matrix Evaluation
# -------------------------------------------------------------

def get_credentials_matrix(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    has_gemini = bool(cfg.get("gemini_api_key", "").strip())
    has_etherscan = bool(cfg.get("etherscan_api_key", "").strip())
    has_arbiscan = bool(cfg.get("arbiscan_api_key", "").strip())
    has_polygonscan = bool(cfg.get("polygonscan_api_key", "").strip())
    has_basescan = bool(cfg.get("basescan_api_key", "").strip())
    has_eth_ws = bool(cfg.get("eth_rpc_ws_url", "").strip())

    return [
        {
            "action_id": "audit_heuristic",
            "name": "Local Contract Heuristic Audit",
            "category": "Contract Auditing",
            "status": "ready",
            "status_label": "Fully Ready",
            "required_keys": [],
            "optional_keys": ["GEMINI_API_KEY"],
            "description": "Offline static heuristic inspection (Reentrancy, tx.origin, assembly, zero-address checks). No external API key required."
        },
        {
            "action_id": "audit_genai",
            "name": "GenAI LLM Deep Contract Audit",
            "category": "Contract Auditing",
            "status": "ready" if has_gemini else "missing",
            "status_label": "Ready" if has_gemini else "Missing Key (Heuristic Only)",
            "required_keys": ["GEMINI_API_KEY"],
            "optional_keys": [],
            "description": "Gemini 2.0 Flash context-isolated code reasoning. Required when running in Strict Real Mode."
        },
        {
            "action_id": "etherscan_mainnet",
            "name": "Ethereum Mainnet Verified Contract Ingestion",
            "category": "Chain Ingestion",
            "status": "ready" if has_etherscan else "optional",
            "status_label": "Configured (Custom Key)" if has_etherscan else "Free Tier (Rate Limited)",
            "required_keys": [],
            "optional_keys": ["ETHERSCAN_API_KEY"],
            "description": "Fetches verified source code from Etherscan API. Rate limited to 5 req/sec with token bucket."
        },
        {
            "action_id": "l2_ingestion",
            "name": "Layer-2 Verified Ingestion (Arbitrum / Polygon / Base)",
            "category": "Chain Ingestion",
            "status": "ready" if (has_arbiscan or has_polygonscan or has_basescan) else "optional",
            "status_label": "Configured" if (has_arbiscan or has_polygonscan or has_basescan) else "Free Tier / Key Optional",
            "required_keys": [],
            "optional_keys": ["ARBISCAN_API_KEY", "POLYGONSCAN_API_KEY", "BASESCAN_API_KEY"],
            "description": "Retrieves multi-file verified source contracts from L2 explorer APIs."
        },
        {
            "action_id": "mempool_real",
            "name": "Real Live Mempool Streaming",
            "category": "Mempool Stream",
            "status": "ready" if has_eth_ws else "missing",
            "status_label": "Ready (Live Node Configured)" if has_eth_ws else "Missing RPC Endpoint",
            "required_keys": ["ETH_RPC_WS_URL"],
            "optional_keys": [],
            "description": "Connects directly to real Ethereum/L2 WebSocket node to capture real-time pending transactions. Requires a valid WebSocket RPC URL."
        }
    ]


# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@app.get("/api/status")
async def get_system_status():
    cfg = load_web_settings()
    selector_enabled = bool(cfg.get("enable_selector_analysis", True))
    frequency_enabled = bool(cfg.get("enable_frequency_analysis", True))
    sandwich_enabled = bool(cfg.get("enable_sandwich_detection", True))
    matrix = get_credentials_matrix(cfg)
    return {
        "status": "ONLINE",
        "version": "2.0.0",
        "mode": "STRICT_REAL" if cfg.get("strict_mode") else "RESILIENT",
        "default_chain": cfg.get("default_chain", "ethereum"),
        "supported_chains": list(settings.chains.keys()),
        "has_gemini_key": bool(cfg.get("gemini_api_key")),
        "has_etherscan_key": bool(cfg.get("etherscan_api_key")),
        "has_rpc_ws": bool(cfg.get("eth_rpc_ws_url", "").strip()),
        "eth_rpc_ws_url": mask_secret(cfg.get("eth_rpc_ws_url", "")),
        "sliding_window": {
            "window_seconds": cfg.get("sliding_window_seconds", 10.0),
            "anomaly_threshold": cfg.get("anomaly_tx_threshold", 5)
        },
        "pipeline_controls": {
            key: bool(cfg.get(key, True))
            for key in (
                "enable_heuristic_engine", "enable_llm_engine",
                "enable_selector_analysis", "enable_frequency_analysis",
                "enable_sandwich_detection", "enable_prompt_neutralization"
            )
        },
        "history_retention": {
            "days": int(cfg.get("history_retention_days", 30)),
            "max_records": int(cfg.get("history_max_records", 1000)),
        },
        "credentials_matrix": matrix
    }


@app.get("/api/overview")
async def get_overview():
    """Small aggregate payload for the operations overview."""
    audits = db.get_audits_paginated(page=1, page_size=6)
    anomalies = db.get_anomalies_paginated(page=1, page_size=6)
    return {
        "recent_audits": audits["items"],
        "recent_anomalies": anomalies["items"],
        "audit_total": audits["total"],
        "anomaly_total": anomalies["total"],
    }


@app.get("/api/demo/samples")
async def get_demo_samples():
    """Returns local test contracts and sample suite for instant demonstration."""
    samples = []
    
    # VulnerableVault
    vault_path = BASE_DIR / "data" / "test_contracts" / "VulnerableVault.sol"
    if vault_path.exists():
        with open(vault_path, "r", encoding="utf-8") as f:
            samples.append({
                "id": "vulnerable_vault",
                "name": "VulnerableVault.sol",
                "category": "Critical Vulnerability Demo",
                "description": "Contains Reentrancy, tx.origin authentication flaw, raw assembly, and embedded prompt injection.",
                "source": f.read()
            })

    # SafeERC20
    safe_path = BASE_DIR / "data" / "test_contracts" / "SafeERC20.sol"
    if safe_path.exists():
        with open(safe_path, "r", encoding="utf-8") as f:
            samples.append({
                "id": "safe_erc20",
                "name": "SafeERC20.sol",
                "category": "Safe Standard Token",
                "description": "A well-architected ERC20 standard token implementation with zero vulnerabilities.",
                "source": f.read()
            })

    # Sample Suite (Interconnected contracts)
    suite_dir = BASE_DIR / "data" / "test_contracts" / "sample_suite"
    suite_contracts = []
    if suite_dir.exists():
        for sf in suite_dir.glob("*.sol"):
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    suite_contracts.append({
                        "name": sf.name,
                        "source": f.read()
                    })
            except Exception:
                continue

    return {
        "single_samples": samples,
        "sample_suite": {
            "name": "DeFi Yield Staking Ecosystem",
            "description": "An interconnected 4-contract system demonstrating inheritance, interfaces, and cross-contract calls.",
            "contracts": suite_contracts
        }
    }


@app.post("/api/audit/contract")
async def audit_contract(req: AuditContractRequest):
    """Audits a single smart contract (either raw source, local file, or explorer 0x address)."""
    cfg = load_web_settings()
    strict_mode = req.strict_mode if req.strict_mode is not None else cfg.get("strict_mode", False)
    
    # Check credentials if strict mode is enabled
    if strict_mode and not cfg.get("gemini_api_key"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Missing Required Credential",
                "message": "Strict Real Mode requires a valid GEMINI_API_KEY. Heuristic fallback is disabled.",
                "action": "Open Settings and enter your Gemini API Key or switch to Resilient Mode."
            }
        )

    pipeline = ChainMindPipeline(
        etherscan_api_key=cfg.get("etherscan_api_key"),
        gemini_api_key=cfg.get("gemini_api_key"),
        chain=req.chain,
        sliding_window_sec=float(cfg.get("sliding_window_seconds", 10.0)),
        anomaly_threshold=int(cfg.get("anomaly_tx_threshold", 5)),
        strict_mode=strict_mode,
        enable_heuristic=bool(cfg.get("enable_heuristic_engine", True)),
        enable_llm=bool(cfg.get("enable_llm_engine", True)),
        enable_prompt_neutralization=bool(cfg.get("enable_prompt_neutralization", True)),
    )

    try:
        # Case A: Address provided
        if req.contract_address:
            addr = req.contract_address.strip()
            if not addr.startswith("0x") or len(addr) != 42:
                raise HTTPException(status_code=400, detail="Invalid Ethereum address. Must start with 0x and be 42 characters.")
            result = await pipeline.audit_etherscan_contract(addr, raw_json_output=False)
            if result.get("status") == "ERROR":
                raise HTTPException(status_code=422, detail=result.get("error", "Failed to retrieve verified contract from Explorer."))
            return result

        # Case B: Direct source code provided
        elif req.source_code and req.source_code.strip():
            target_name = req.target_path or "UploadedContract.sol"
            result = await pipeline.audit_smart_contract_source(
                raw_source=req.source_code,
                target_address=f"WebUI::{target_name}",
                raw_json_output=False
            )
            return result

        # Case C: Target file path provided
        elif req.target_path:
            p = BASE_DIR / req.target_path
            if not p.exists():
                raise HTTPException(status_code=404, detail=f"File not found: {req.target_path}")
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read()
            result = await pipeline.audit_smart_contract_source(
                raw_source=src,
                target_address=f"LocalFile::{p.name}",
                raw_json_output=False
            )
            return result
        else:
            raise HTTPException(status_code=400, detail="Either source_code, target_path, or contract_address must be provided.")

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Audit failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/audit/detect-relationships")
async def detect_contract_relationships(req: BatchAuditRequest):
    """
    Parses a set of contract files, discovers imports, inheritance, interfaces,
    and returns an interactive dependency graph with batched execution groups.
    """
    files_map = {}
    for c in req.contracts:
        name = c.get("name", "Contract.sol")
        src = c.get("source", "")
        files_map[name] = ContractRelationshipDetector.analyze_source(src, file_identifier=name)

    graph = ContractRelationshipDetector.build_dependency_graph(files_map)
    return graph


@app.post("/api/audit/batch")
async def audit_batch(req: BatchAuditRequest):
    """
    Executes an aggregated batch audit across multiple contracts,
    detects relationships, and evaluates all contracts with a comparison matrix.
    """
    cfg = load_web_settings()
    strict_mode = req.strict_mode if req.strict_mode is not None else cfg.get("strict_mode", False)

    pipeline = ChainMindPipeline(
        etherscan_api_key=cfg.get("etherscan_api_key"),
        gemini_api_key=cfg.get("gemini_api_key"),
        chain=req.chain,
        sliding_window_sec=float(cfg.get("sliding_window_seconds", 10.0)),
        anomaly_threshold=int(cfg.get("anomaly_tx_threshold", 5)),
        strict_mode=strict_mode,
        enable_heuristic=bool(cfg.get("enable_heuristic_engine", True)),
        enable_llm=bool(cfg.get("enable_llm_engine", True)),
        enable_prompt_neutralization=bool(cfg.get("enable_prompt_neutralization", True)),
    )

    # 1. Detect relationships
    files_map = {}
    for c in req.contracts:
        name = c.get("name", "Contract.sol")
        src = c.get("source", "")
        files_map[name] = ContractRelationshipDetector.analyze_source(src, file_identifier=name)
    graph = ContractRelationshipDetector.build_dependency_graph(files_map)

    # 2. Audit each contract
    individual_reports = []
    total_findings = 0
    highest_risk = 1

    for c in req.contracts:
        name = c.get("name", "Contract.sol")
        src = c.get("source", "")
        if not src.strip():
            continue
        try:
            report = await pipeline.audit_smart_contract_source(
                raw_source=src,
                target_address=f"Batch::{name}",
                raw_json_output=False
            )
            report["contract_name"] = name
            risk = report.get("risk_score", 1)
            highest_risk = max(highest_risk, risk)
            total_findings += len(report.get("security_findings", []))
            individual_reports.append(report)
        except Exception as e:
            individual_reports.append({
                "contract_name": name,
                "status": "ERROR",
                "error": str(e),
                "risk_score": 0
            })

    return {
        "status": "SUCCESS",
        "batch_size": len(individual_reports),
        "total_findings": total_findings,
        "max_risk_score": highest_risk,
        "overall_status": "CRITICAL" if highest_risk >= 7 else ("WARNING" if highest_risk >= 4 else "SAFE"),
        "dependency_graph": graph,
        "reports": individual_reports
    }


@app.post("/api/audit/refine")
async def refine_audited_contract(req: RefineContractRequest):
    """Generate a safer contract only when the completed audit contains findings."""
    if not req.findings:
        return {
            "status": "SAFE_NO_REWRITE",
            "contract_source": req.source_code,
            "changes": [],
            "explanation": "No vulnerabilities were identified, so no replacement contract was generated."
        }
    cfg = load_web_settings()
    auditor = ChainMindPipeline(
        gemini_api_key=cfg.get("gemini_api_key"),
        chain=cfg.get("default_chain", "ethereum"),
        strict_mode=bool(cfg.get("strict_mode", False)),
        enable_heuristic=bool(cfg.get("enable_heuristic_engine", True)),
        enable_llm=bool(cfg.get("enable_llm_engine", True)),
        enable_prompt_neutralization=bool(cfg.get("enable_prompt_neutralization", True)),
    ).llm_auditor
    try:
        return await auditor.generate_refined_contract(
            req.source_code, req.findings, target_address=req.target_address
        )
    except Exception as exc:
        logger.error("Contract refinement failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


# -------------------------------------------------------------
# Anomaly Insights Report Generator Helper
# -------------------------------------------------------------

def generate_anomaly_insights_report(
    parsed_hex: Dict[str, Any],
    window_meta: Dict[str, Any],
    sandwich_meta: Optional[Dict[str, Any]] = None,
    classification_override: Optional[str] = None,
    reason_override: Optional[str] = None
) -> Dict[str, Any]:
    """
    Prepares a detailed, actionable insights report as soon as an anomaly is observed.
    """
    report_id = f"ANOMALY-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{str(parsed_hex.get('tx_hash', '0x'))[-6:]}"
    is_sandwich = sandwich_meta is not None and sandwich_meta.get("is_sandwich")
    sender = str(parsed_hex.get("sender") or "0x0")
    target_pool = parsed_hex.get("target")
    value_eth = parsed_hex.get("value_eth", 0)
    decoded_params = parsed_hex.get("decoded_parameters") or {}
    
    anomaly_type = classification_override or ("MEV_SANDWICH_ATTACK" if is_sandwich else parsed_hex.get("payload_classification", "HIGH_FREQUENCY_BURST"))
    
    if is_sandwich:
        severity = "CRITICAL"
        title = "Malicious MEV Sandwich Attack Detected"
        reason = reason_override or sandwich_meta.get("detection_reason", "Front-running and back-running victim swap around liquidity pool.")
        attacker = sandwich_meta.get("attacker_address")
        victim = sandwich_meta.get("victim_sender")
        impact = "Victim transaction suffered severe price slippage exploitation. Attacker extracted risk-free arbitrage profit from pool imbalance."
        mitigations = [
            "Submit transactions through MEV-protected RPC endpoints (e.g. Flashbots Protect, Eden Network).",
            "Enforce strict maximum slippage tolerances (e.g. <= 0.5%) on DEX trade routers.",
            "Implement commit-reveal schemes or TWAP price feeds to mitigate single-block sandwiching."
        ]
    elif anomaly_type == "SUSPICIOUS_HIGH_RISK_CALL":
        severity = "CRITICAL"
        title = "High-Risk Destructive Function Call Flagged"
        reason = reason_override or f"Invocation of high-risk selector {parsed_hex.get('function_selector')} ({parsed_hex.get('decoded_function_name', 'Unknown')})"
        attacker = sender
        victim = "Target Contract Holders"
        impact = "Potential emergency drain or contract state liquidation attempted in mempool prior to block finality."
        mitigations = [
            "Verify caller permissions: Ensure only multisig or timelock can trigger administrative methods.",
            "Use decentralized rate limiters and multi-party approval requirements on critical withdrawal flows."
        ]
    elif anomaly_type == "INFINITE_APPROVAL":
        severity = "WARNING"
        title = "Unlimited ERC20 Token Approval Detected"
        spender = decoded_params.get("spender", "Unknown Contract")
        reason = reason_override or f"Unlimited token allowance granted to {spender}"
        attacker = sender
        victim = "Wallet Assets / Token Holder"
        impact = "Granting MAX_UINT256 allowance gives the spender contract unlimited access to all present and future tokens in the caller's wallet."
        mitigations = [
            "Use exact amount approvals instead of type(uint256).max.",
            "Use EIP-2612 permit with single-use signatures where possible.",
            "Periodically revoke allowances for unused dApps using Revoke.cash or Etherscan."
        ]
    elif anomaly_type == "HIGH_GAS_SPIKE":
        severity = "WARNING"
        gas_val = parsed_hex.get("gas_price_gwei", 0)
        title = f"Extreme Gas Price MEV Surge Detected ({gas_val:.1f} Gwei)"
        reason = reason_override or f"High gas price anomaly: {gas_val:.1f} Gwei"
        attacker = sender
        victim = "Public Mempool Priority Queue"
        impact = "Transaction paying gas fees significantly above network average, indicating high-priority queue jumping or MEV arbitrage execution."
        mitigations = [
            "Use Flashbots Protect / private RPC endpoints to avoid public mempool gas auctions.",
            "Set reasonable maxFeePerGas caps on transactions."
        ]
    elif anomaly_type == "LARGE_VALUE_TRANSFER":
        severity = "CRITICAL" if value_eth >= 50 else "WARNING"
        title = f"High-Value Transaction Transfer Flagged ({value_eth:.4f} ETH)"
        reason = reason_override or f"High-value transfer of {value_eth:.4f} ETH detected in mempool."
        attacker = sender
        victim = "Whale Wallet / Exchange Liquidity"
        impact = "Substantial on-chain liquidity movement. Potential large swap or whale liquidation in progress."
        mitigations = [
            "Monitor destination address for multisig/CEX deposit authenticity.",
            "Track recipient pool for sudden price shifts."
        ]
    elif anomaly_type == "PROXY_UPGRADE":
        severity = "WARNING"
        title = "Smart Contract Upgrade / Governance Invocation"
        reason = reason_override or f"Privileged upgrade call {parsed_hex.get('decoded_function_name', 'upgrade')} invoked."
        attacker = sender
        victim = "Contract Implementation & Storage"
        impact = "Privileged state modification call detected. If not submitted by the legitimate owner or multisig, this could alter contract implementation logic."
        mitigations = [
            "Verify sender is authorized multisig or timelock.",
            "Enforce timelock delays on critical proxy upgrades."
        ]
    else:
        count_in_w = window_meta.get("count_in_window", 1)
        severity = "CRITICAL" if count_in_w >= 5 else "WARNING"
        title = "High-Frequency Transaction Flooding Anomaly" if count_in_w >= 5 else "Elevated Sender Velocity"
        reason = reason_override or window_meta.get("anomaly_reason", "Abnormal burst rate detected over sliding window.")
        attacker = sender
        victim = "Network Validators & Contract Mempool"
        impact = "Potential DDoS exhaustion, spam bot front-running, or automated liquidator hammering."
        mitigations = [
            "Implement sliding-window nonce and account rate limiting at smart contract entry points.",
            "Leverage dynamic gas priority escalations or CAPTCHA/proof-of-work on off-chain relayers."
        ]

    return {
        "report_id": report_id,
        "title": title,
        "severity": severity,
        "anomaly_type": anomaly_type,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "transaction": {
            "tx_hash": parsed_hex.get("tx_hash"),
            "sender": sender,
            "target": target_pool,
            "function_selector": parsed_hex.get("function_selector"),
            "function_name": parsed_hex.get("decoded_function_name", "Unknown"),
            "classification": anomaly_type,
            "gas_price_gwei": parsed_hex.get("gas_price_gwei", 0),
            "calldata_length": parsed_hex.get("calldata_length_bytes", 0)
        },
        "frequency_metrics": {
            "count_in_window": window_meta.get("count_in_window", 1),
            "window_seconds": window_meta.get("window_seconds", 10.0),
            "calculated_rate_tx_per_sec": round(window_meta.get("count_in_window", 1) / max(0.1, window_meta.get("window_seconds", 10.0)), 2)
        },
        "participants": {
            "attacker_or_initiator": attacker,
            "victim": victim,
            "target_contract_or_pool": target_pool
        },
        "impact_assessment": impact,
        "actionable_mitigations": mitigations
    }


# -------------------------------------------------------------
# History & Anomaly Records (Paginated)
# -------------------------------------------------------------

@app.get("/api/history/audits")
async def get_audit_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: str = Query(""),
    risk_min: int = Query(0, ge=0, le=10),
    risk_max: int = Query(10, ge=0, le=10),
    sort_order: str = Query("desc")
):
    """Returns paginated contract audits with risk level and sort filtering."""
    cfg = load_web_settings()
    db.cleanup_history(
        retention_days=int(cfg.get("history_retention_days", 30)),
        max_records=int(cfg.get("history_max_records", 1000)),
    )
    return db.get_audits_paginated(
        page=page, page_size=page_size, search=search,
        risk_min=risk_min, risk_max=risk_max,
        sort_order=sort_order
    )


@app.get("/api/history/anomalies")
async def get_anomaly_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: str = Query(""),
    classification: str = Query(""),
    sort_order: str = Query("desc")
):
    """Returns paginated mempool anomalies with classification and sort filtering."""
    cfg = load_web_settings()
    db.cleanup_history(
        retention_days=int(cfg.get("history_retention_days", 30)),
        max_records=int(cfg.get("history_max_records", 1000)),
    )
    return db.get_anomalies_paginated(
        page=page, page_size=page_size, search=search,
        classification=classification,
        sort_order=sort_order
    )


@app.get("/api/history/audit/{audit_id}")
async def get_audit_detail(audit_id: int):
    record = db.get_audit_by_id(audit_id)
    if not record:
        raise HTTPException(status_code=404, detail="Audit record not found")
    return record


@app.get("/api/history/anomaly/{anomaly_id}")
async def get_anomaly_detail(anomaly_id: int):
    record = db.get_anomaly_by_id(anomaly_id)
    if not record:
        raise HTTPException(status_code=404, detail="Anomaly record not found")
    return record


# -------------------------------------------------------------
# Settings & Authentication
# -------------------------------------------------------------

@app.post("/api/settings/verify-auth")
async def verify_auth(req: AuthVerifyRequest):
    cfg = load_web_settings()
    expected = cfg.get("admin_passcode", "chainmind-admin")
    if req.passcode == expected:
        return {"authenticated": True, "message": "Access granted"}
    raise HTTPException(status_code=401, detail="Invalid admin passcode")


@app.get("/api/settings/load")
async def get_settings(auth_passcode: Optional[str] = Header(None, alias="X-Admin-Passcode")):
    cfg = load_web_settings()
    expected = cfg.get("admin_passcode", "chainmind-admin")
    if auth_passcode != expected:
        raise HTTPException(status_code=401, detail="Authentication required to view settings")

    matrix = get_credentials_matrix(cfg)
    return {
        "settings": public_settings(cfg),
        "credentials_matrix": matrix
    }


@app.post("/api/settings/save")
async def update_settings(req: UpdateSettingsRequest):
    """Saves updated settings and credentials after authentication."""
    cfg = load_web_settings()
    expected = cfg.get("admin_passcode", "chainmind-admin")
    if req.passcode != expected:
        raise HTTPException(status_code=401, detail="Invalid admin passcode")

    new_cfg = req.settings
    # If user provided a new passcode in the settings
    if "new_admin_passcode" in new_cfg and str(new_cfg["new_admin_passcode"]).strip():
        cfg["admin_passcode"] = str(new_cfg["new_admin_passcode"]).strip()

    for key in [
        "gemini_api_key", "etherscan_api_key", "arbiscan_api_key",
        "polygonscan_api_key", "basescan_api_key", "optimistic_api_key",
        "eth_rpc_ws_url", "eth_rpc_http_url", "default_chain",
        "strict_mode", "sliding_window_seconds", "anomaly_tx_threshold"
        , "enable_heuristic_engine", "enable_llm_engine",
        "enable_selector_analysis", "enable_frequency_analysis",
        "enable_sandwich_detection", "enable_prompt_neutralization",
        "history_retention_days", "history_max_records"
    ]:
        if key in SECRET_SETTING_KEYS and key in new_cfg:
            value = str(new_cfg[key] or "").strip()
            if value and not value.startswith("••••••••"):
                cfg[key] = value
        elif key in new_cfg:
            cfg[key] = new_cfg[key]

    try:
        cfg["sliding_window_seconds"] = max(
            1.0, min(300.0, float(cfg.get("sliding_window_seconds", 10.0)))
        )
        cfg["anomaly_tx_threshold"] = max(
            2, min(1000, int(cfg.get("anomaly_tx_threshold", 5)))
        )
        cfg["history_retention_days"] = max(
            1, min(3650, int(cfg.get("history_retention_days", 30)))
        )
        cfg["history_max_records"] = max(
            50, min(100000, int(cfg.get("history_max_records", 1000)))
        )
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Sliding window and anomaly threshold must be valid numbers."
        )

    if cfg.get("default_chain") not in settings.chains:
        raise HTTPException(status_code=400, detail="Unsupported default chain.")

    save_web_settings(cfg)
    db.cleanup_history(
        retention_days=cfg["history_retention_days"],
        max_records=cfg["history_max_records"],
    )
    return {
        "success": True,
        "message": "Settings saved successfully",
        "credentials_matrix": get_credentials_matrix(cfg)
    }


# -------------------------------------------------------------
# Exporters (HTML, SARIF, Patch)
# -------------------------------------------------------------

@app.post("/api/export/html")
async def export_html(report: Dict[str, Any]):
    html_content = HTMLReporter.generate_html(report)
    return Response(content=html_content, media_type="text/html")


@app.post("/api/export/sarif")
async def export_sarif(report: Dict[str, Any]):
    sarif_data = SARIFExporter.generate_sarif(report, file_uri=report.get("target_address", "contract.sol"))
    return JSONResponse(content=sarif_data)


@app.post("/api/export/patch")
async def export_patch(data: Dict[str, Any]):
    source = data.get("source_code", "")
    findings = data.get("findings", [])
    patch_text = RemediationEngine.generate_patch_file("contract.sol", findings)
    return Response(content=patch_text, media_type="text/x-diff")


# -------------------------------------------------------------
# WebSocket: Continuous Real-Time Mempool Streaming
# -------------------------------------------------------------

@app.websocket("/ws/mempool")
async def websocket_mempool(websocket: WebSocket):
    """
    Continuous real-time mempool evaluation WebSocket:
    - Connects to real Web3 WebSocket RPC endpoints (no synthetic fake streams)
    - Signals Traffic Lights: Green (safe routine tx), Yellow (elevated frequency / gas), Red (burst anomaly / critical selector)
    - If RPC endpoint is unconfigured or fails, emits a clear credential/connection error to the user
    """
    await websocket.accept()
    cfg = load_web_settings()
    selector_enabled = bool(cfg.get("enable_selector_analysis", True))
    frequency_enabled = bool(cfg.get("enable_frequency_analysis", True))
    sandwich_enabled = bool(cfg.get("enable_sandwich_detection", True))

    rate_tracker = SlidingWindowRateTracker(
        window_seconds=float(cfg.get("sliding_window_seconds", 10.0)),
        threshold_count=int(cfg.get("anomaly_tx_threshold", 5))
    )
    sandwich_detector = SandwichDetector(window_seconds=5.0)

    is_running = True
    chain = cfg.get("default_chain", "ethereum")

    # Command listener task
    async def listen_commands():
        nonlocal is_running, chain
        try:
            while True:
                msg = await websocket.receive_text()
                cmd = json.loads(msg)
                action = cmd.get("action")
                if action == "pause":
                    is_running = False
                elif action == "start" or action == "resume":
                    is_running = True
                    chain = cmd.get("chain", chain)
                elif action == "update_config":
                    if "chain" in cmd:
                        chain = cmd["chain"]
        except Exception:
            is_running = False

    cmd_task = asyncio.create_task(listen_commands())

    try:
        chain_cfg = settings.get_chain_config(chain) if chain in settings.chains else None
        ws_url = cfg.get("eth_rpc_ws_url") or (chain_cfg["ws_rpc"] if chain_cfg else None)
        http_rpc = cfg.get("eth_rpc_http_url") or (chain_cfg["http_rpc"] if chain_cfg else None)

        if not ws_url or not ws_url.strip():
            await websocket.send_text(json.dumps({
                "signal": "red",
                "error": True,
                "error_code": "MISSING_RPC_URL",
                "one_line_summary": "Missing RPC Endpoint: Real mempool streaming requires an active Web3 WebSocket URL.",
                "details": "Please configure your RPC WebSocket URL (Infura, Alchemy, or public node) in Settings -> Node Endpoints."
            }))
            return

        # Send initial connecting status
        await websocket.send_text(json.dumps({
            "status": "CONNECTING",
            "provider": mask_secret(ws_url),
            "chain": chain,
            "one_line_summary": f"Connecting to live Ethereum mempool node via WebSockets ({chain})..."
        }))

        listener = MempoolListener(ws_url=ws_url, http_rpc_url=http_rpc)

        async for tx in listener.listen_live():
            if not is_running:
                await asyncio.sleep(0.3)
                continue

            if tx.get("_error"):
                await websocket.send_text(json.dumps({
                    "signal": "red",
                    "error": True,
                    "error_code": "RPC_DISCONNECTED",
                    "one_line_summary": tx.get("error", "RPC Connection Failed"),
                    "details": tx.get("details", "Connection to the Ethereum RPC WebSocket failed. Verify endpoint URL or API credentials in Settings.")
                }))
                await asyncio.sleep(2.0)
                continue

            # Layer 1: Ingestion & Normalization
            try:
                l1_payload = Normalizer.process_mempool_transaction(tx)
            except Exception as norm_err:
                logger.debug(f"Transaction normalization error: {norm_err}")
                continue

            # Layer 2: Hex Engine Parsing
            parsed_hex = HexEngine.parse_transaction(tx)
            sender = parsed_hex.get("sender", "0x0")
            timestamp = tx.get("timestamp")
            value_eth = parsed_hex.get("value_eth", 0)

            # Real Sliding Window Rate Tracking
            if frequency_enabled:
                is_anomalous, count, window_meta = rate_tracker.record_transaction(sender, timestamp=timestamp)
            else:
                is_anomalous, count, window_meta = False, 1, {
                    "count_in_window": 1,
                    "window_seconds": float(cfg.get("sliding_window_seconds", 10.0)),
                    "anomaly_reason": "Frequency analysis disabled in Settings."
                }
            # Real Sandwich Attack Detection
            if sandwich_enabled:
                is_sandwich, sandwich_meta = sandwich_detector.record_and_evaluate(parsed_hex, timestamp=timestamp)
            else:
                is_sandwich, sandwich_meta = False, {}

            classification = parsed_hex.get("payload_classification", "STANDARD_CALL") if selector_enabled else "STANDARD_CALL"
            high_gas = parsed_hex.get("high_gas_anomaly", False)
            decoded_params = parsed_hex.get("decoded_parameters") or {}
            is_infinite_approval = decoded_params.get("is_infinite_approval", False)
            sig_info = parsed_hex.get("signature_info") or {}
            sig_risk = sig_info.get("risk_level", "LOW")

            # ── Determine real Traffic Light Signal and Classification Tag ──
            classification_tag = "STANDARD_CALL"
            if is_sandwich or classification == "SUSPICIOUS_HIGH_RISK_CALL" or is_anomalous or value_eth >= 50:
                signal = "red"
                if is_sandwich:
                    classification_tag = "MEV_SANDWICH_ATTACK"
                    one_line_summary = f"[MEV SANDWICH ATTACK] Attacker {str(sandwich_meta.get('attacker_address', ''))[:10]}... front-ran victim on pool {str(sandwich_meta.get('target_pool', ''))[:10]}..."
                elif classification == "SUSPICIOUS_HIGH_RISK_CALL":
                    classification_tag = "SUSPICIOUS_HIGH_RISK_CALL"
                    one_line_summary = f"[CRITICAL CALL] High-risk selector {parsed_hex.get('function_selector')} ({parsed_hex.get('decoded_function_name')}) from {sender[:10]}..."
                elif value_eth >= 50:
                    classification_tag = "LARGE_VALUE_TRANSFER"
                    one_line_summary = f"[LARGE TRANSFER] {value_eth:.4f} ETH moved by {sender[:10]}... — high-value transaction flagged"
                else:
                    classification_tag = "HIGH_FREQUENCY_BURST"
                    one_line_summary = f"[BURST ANOMALY] Real Sender {sender[:10]}... sent {count} transactions in {window_meta.get('window_seconds')}s"
            elif count >= 3 or high_gas or is_infinite_approval or value_eth >= 10 or sig_risk == "HIGH":
                signal = "yellow"
                if is_infinite_approval:
                    classification_tag = "INFINITE_APPROVAL"
                    one_line_summary = f"[INFINITE APPROVAL] Unlimited token allowance granted by {sender[:10]}... to {decoded_params.get('spender', '?')[:10]}..."
                elif value_eth >= 10:
                    classification_tag = "LARGE_VALUE_TRANSFER"
                    one_line_summary = f"[ELEVATED VALUE] {value_eth:.4f} ETH transfer by {sender[:10]}... — above threshold"
                elif high_gas:
                    classification_tag = "HIGH_GAS_SPIKE"
                    one_line_summary = f"[HIGH GAS] {parsed_hex.get('gas_price_gwei', 0):.1f} Gwei from {sender[:10]}... — potential frontrunning"
                elif sig_risk == "HIGH":
                    classification_tag = "PROXY_UPGRADE"
                    one_line_summary = f"[PROXY UPGRADE] {parsed_hex.get('decoded_function_name', 'upgradeCall')} invoked by {sender[:10]}... — elevated privilege action"
                else:
                    classification_tag = "ELEVATED_ACTIVITY"
                    one_line_summary = f"[ELEVATED ACTIVITY] Real Sender {sender[:10]}... ({count} txs in {window_meta.get('window_seconds')}s, Gas: {parsed_hex.get('gas_price_gwei', 0):.1f} Gwei)"
            else:
                signal = "green"
                func_name = parsed_hex.get("decoded_function_name") or "Standard Transfer"
                gas_val = parsed_hex.get("gas_price_gwei", 0)
                one_line_summary = f"Real Network Call: {func_name} ({gas_val:.1f} Gwei) to {str(parsed_hex.get('target') or '')[:10]}..."

            anomaly_report = None
            if signal in ("yellow", "red"):
                anomaly_report = generate_anomaly_insights_report(
                    parsed_hex=parsed_hex,
                    window_meta=window_meta,
                    sandwich_meta=sandwich_meta if is_sandwich else None,
                    classification_override=classification_tag,
                    reason_override=one_line_summary
                )

            # Persist all live stream events into the database audit trail
            try:
                if is_sandwich:
                    db.save_mempool_anomaly({
                        "tx_hash": sandwich_meta.get("backrun_tx") or parsed_hex.get("tx_hash"),
                        "sender": sandwich_meta.get("attacker_address") or sender,
                        "target": sandwich_meta.get("target_pool") or parsed_hex.get("target"),
                        "function_selector": parsed_hex.get("function_selector"),
                        "classification": "MEV_SANDWICH_ATTACK",
                        "anomaly_reason": sandwich_meta.get("detection_reason") or one_line_summary
                    }, {
                        "count_in_window": 3,
                        "window_seconds": 5.0,
                        "anomaly_reason": sandwich_meta.get("detection_reason") or one_line_summary
                    })
                else:
                    db.save_mempool_anomaly({
                        "tx_hash": parsed_hex.get("tx_hash"),
                        "sender": sender,
                        "target": parsed_hex.get("target"),
                        "function_selector": parsed_hex.get("function_selector"),
                        "classification": classification_tag if classification_tag != "STANDARD_CALL" else classification,
                        "anomaly_reason": one_line_summary
                    }, {
                        "count_in_window": count,
                        "window_seconds": window_meta.get("window_seconds", 10.0),
                        "anomaly_reason": one_line_summary
                    })
            except Exception as e:
                logger.warning(f"Failed to persist real mempool transaction: {e}")

            # Send real event to client
            event_payload = {
                "signal": signal,
                "one_line_summary": one_line_summary,
                "tx": {
                    "tx_hash": parsed_hex.get("tx_hash"),
                    "sender": sender,
                    "target": parsed_hex.get("target"),
                    "value_wei": parsed_hex.get("value_wei"),
                    "value_eth": value_eth,
                    "gas_price_gwei": parsed_hex.get("gas_price_gwei", 0),
                    "function_selector": parsed_hex.get("function_selector"),
                    "decoded_name": parsed_hex.get("decoded_function_name"),
                    "classification": classification_tag,
                    "count_in_window": count,
                    "window_seconds": window_meta.get("window_seconds", 10.0),
                    "timestamp": timestamp or datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "high_gas_anomaly": high_gas,
                    "is_infinite_approval": is_infinite_approval,
                    "risk_level": sig_risk
                },
                "anomaly_report": anomaly_report
            }

            await websocket.send_text(json.dumps(event_payload))
            await asyncio.sleep(0.05)

    except WebSocketDisconnect:
        logger.info("Mempool WebSocket disconnected by client")
    except Exception as exc:
        logger.error(f"WebSocket streaming error: {exc}")
    finally:
        cmd_task.cancel()




# -------------------------------------------------------------
# Static Web App Mount
# -------------------------------------------------------------

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/favicon.ico")
async def serve_favicon():
    """Keep browser previews free of a noisy missing-favicon request."""
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
      <rect width="64" height="64" rx="16" fill="#d95f37"/>
      <text x="32" y="40" text-anchor="middle" font-family="Arial" font-size="22"
        font-weight="700" fill="white">CM</text>
    </svg>"""
    return Response(content=svg, media_type="image/svg+xml")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Chain-Mind Auditor Web Frontend Initializing...</h1>"

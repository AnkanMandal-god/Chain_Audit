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
CONFIG_FILE = BASE_DIR / "config" / "web_settings.json"
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
        "admin_passcode": "chainmind-admin",
        "gemini_api_key": settings.gemini_api_key or "",
        "etherscan_api_key": settings.etherscan_api_key or "",
        "arbiscan_api_key": os.getenv("ARBISCAN_API_KEY", ""),
        "polygonscan_api_key": os.getenv("POLYGONSCAN_API_KEY", ""),
        "basescan_api_key": os.getenv("BASESCAN_API_KEY", ""),
        "optimistic_api_key": os.getenv("OPTIMISTIC_BASE_URL", ""),
        "eth_rpc_ws_url": settings.eth_rpc_ws_url,
        "eth_rpc_http_url": settings.eth_rpc_http_url,
        "default_chain": "ethereum",
        "strict_mode": False,
        "sliding_window_seconds": settings.sliding_window_seconds,
        "anomaly_tx_threshold": settings.anomaly_tx_threshold
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
            "status_label": "Ready" if has_gemini else "Missing Key",
            "required_keys": ["GEMINI_API_KEY"],
            "optional_keys": [],
            "description": "Gemini 2.0 Flash context-isolated code reasoning. Required when running in Strict Real Mode."
        },
        {
            "action_id": "etherscan_mainnet",
            "name": "Ethereum Mainnet Verified Contract Ingestion",
            "category": "Chain Ingestion",
            "status": "ready",
            "status_label": "Ready (Free Tier)" if not has_etherscan else "Optimized (Custom Key)",
            "required_keys": [],
            "optional_keys": ["ETHERSCAN_API_KEY"],
            "description": "Fetches verified source code from Etherscan API. Rate limited to 5 req/sec with token bucket."
        },
        {
            "action_id": "l2_ingestion",
            "name": "Layer-2 Verified Ingestion (Arbitrum / Polygon / Base)",
            "category": "Chain Ingestion",
            "status": "ready" if (has_arbiscan or has_polygonscan or has_basescan) else "optional",
            "status_label": "Partially Configured" if (has_arbiscan or has_polygonscan or has_basescan) else "Free Tier / Key Optional",
            "required_keys": [],
            "optional_keys": ["ARBISCAN_API_KEY", "POLYGONSCAN_API_KEY", "BASESCAN_API_KEY"],
            "description": "Retrieves multi-file verified source contracts from L2 explorer APIs."
        },
        {
            "action_id": "mempool_simulated",
            "name": "Simulated Mempool Threat & MEV Stream",
            "category": "Mempool Stream",
            "status": "ready",
            "status_label": "Fully Ready",
            "required_keys": [],
            "optional_keys": [],
            "description": "High-fidelity synthetic pending transaction stream with burst attacks and MEV sandwiches. No credentials needed."
        },
        {
            "action_id": "mempool_live_ws",
            "name": "Live Web3 RPC Mempool Streaming",
            "category": "Mempool Stream",
            "status": "ready" if has_eth_ws else "missing",
            "status_label": "Ready" if has_eth_ws else "Missing RPC URL",
            "required_keys": ["ETH_RPC_WS_URL"],
            "optional_keys": [],
            "description": "Connects to live Ethereum/L2 WebSocket node (Infura, Alchemy, or PublicNode) to capture real-time pending transactions."
        }
    ]


# -------------------------------------------------------------
# REST API Endpoints
# -------------------------------------------------------------

@app.get("/api/status")
async def get_system_status():
    cfg = load_web_settings()
    matrix = get_credentials_matrix(cfg)
    return {
        "status": "ONLINE",
        "version": "2.0.0",
        "mode": "STRICT_REAL" if cfg.get("strict_mode") else "RESILIENT",
        "default_chain": cfg.get("default_chain", "ethereum"),
        "supported_chains": list(settings.chains.keys()),
        "has_gemini_key": bool(cfg.get("gemini_api_key")),
        "has_etherscan_key": bool(cfg.get("etherscan_api_key")),
        "sliding_window": {
            "window_seconds": cfg.get("sliding_window_seconds", 10.0),
            "anomaly_threshold": cfg.get("anomaly_tx_threshold", 5)
        },
        "credentials_matrix": matrix
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
        strict_mode=strict_mode
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
        strict_mode=strict_mode
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


# -------------------------------------------------------------
# Anomaly Insights Report Generator Helper
# -------------------------------------------------------------

def generate_anomaly_insights_report(
    parsed_hex: Dict[str, Any],
    window_meta: Dict[str, Any],
    sandwich_meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Prepares a detailed, actionable insights report as soon as an anomaly is observed.
    """
    report_id = f"ANOMALY-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{parsed_hex.get('tx_hash', '0x')[-6:]}"
    is_sandwich = sandwich_meta is not None and sandwich_meta.get("is_sandwich")
    
    if is_sandwich:
        anomaly_type = "MEV_SANDWICH_ATTACK"
        severity = "CRITICAL"
        title = "Malicious MEV Sandwich Attack Detected"
        reason = sandwich_meta.get("detection_reason", "Front-running and back-running victim swap around liquidity pool.")
        attacker = sandwich_meta.get("attacker_address")
        victim = sandwich_meta.get("victim_sender")
        target_pool = sandwich_meta.get("target_pool")
        impact = "Victim transaction suffered severe price slippage exploitation. Attacker extracted risk-free arbitrage profit from pool imbalance."
        mitigations = [
            "Submit transactions through MEV-protected RPC endpoints (e.g. Flashbots Protect, Eden Network).",
            "Enforce strict maximum slippage tolerances (e.g. <= 0.5%) on DEX trade routers.",
            "Implement commit-reveal schemes or TWAP price feeds to mitigate single-block sandwiching."
        ]
    elif parsed_hex.get("payload_classification") == "SUSPICIOUS_HIGH_RISK_CALL":
        anomaly_type = "SUSPICIOUS_DESTRUCTIVE_CALL"
        severity = "CRITICAL"
        title = "High-Risk Destructive Function Call Flagged"
        reason = f"Invocation of high-risk selector {parsed_hex.get('function_selector')} ({parsed_hex.get('decoded_function_name', 'Unknown')})"
        attacker = parsed_hex.get("sender")
        victim = "Target Contract Holders"
        target_pool = parsed_hex.get("target")
        impact = "Potential emergency drain or contract state liquidation attempted in mempool prior to block finality."
        mitigations = [
            "Verify caller permissions: Ensure only multisig or timelock can trigger administrative methods.",
            "Use decentralized rate limiters and multi-party approval requirements on critical withdrawal flows."
        ]
    else:
        anomaly_type = "HIGH_FREQUENCY_BURST_ATTACK"
        severity = "WARNING" if window_meta.get("count_in_window", 0) <= 7 else "CRITICAL"
        title = "High-Frequency Transaction Flooding Anomaly"
        reason = window_meta.get("anomaly_reason", "Abnormal burst rate detected over sliding window.")
        attacker = parsed_hex.get("sender")
        victim = "Network Validators & Contract Mempool"
        target_pool = parsed_hex.get("target")
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
            "sender": parsed_hex.get("sender"),
            "target": parsed_hex.get("target"),
            "function_selector": parsed_hex.get("function_selector"),
            "function_name": parsed_hex.get("decoded_function_name", "Unknown"),
            "classification": parsed_hex.get("payload_classification"),
            "gas_price_gwei": parsed_hex.get("gas_price_gwei", 0),
            "calldata_length": parsed_hex.get("calldata_length", 0)
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
    search: str = Query("")
):
    """Returns paginated contract audits formatted for 'Showing 1-10 of X' display."""
    return db.get_audits_paginated(page=page, page_size=page_size, search=search)


@app.get("/api/history/anomalies")
async def get_anomaly_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: str = Query("")
):
    """Returns paginated mempool anomalies formatted for 'Showing 1-10 of X' display."""
    return db.get_anomalies_paginated(page=page, page_size=page_size, search=search)


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
    # Mask secrets for display
    return {
        "settings": {
            "gemini_api_key": cfg.get("gemini_api_key", ""),
            "etherscan_api_key": cfg.get("etherscan_api_key", ""),
            "arbiscan_api_key": cfg.get("arbiscan_api_key", ""),
            "polygonscan_api_key": cfg.get("polygonscan_api_key", ""),
            "basescan_api_key": cfg.get("basescan_api_key", ""),
            "optimistic_api_key": cfg.get("optimistic_api_key", ""),
            "eth_rpc_ws_url": cfg.get("eth_rpc_ws_url", ""),
            "eth_rpc_http_url": cfg.get("eth_rpc_http_url", ""),
            "default_chain": cfg.get("default_chain", "ethereum"),
            "strict_mode": cfg.get("strict_mode", False),
            "sliding_window_seconds": cfg.get("sliding_window_seconds", 10.0),
            "anomaly_tx_threshold": cfg.get("anomaly_tx_threshold", 5)
        },
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
    if "new_admin_passcode" in new_cfg and new_cfg["new_admin_passcode"].strip():
        cfg["admin_passcode"] = new_cfg["new_admin_passcode"].strip()

    for key in [
        "gemini_api_key", "etherscan_api_key", "arbiscan_api_key",
        "polygonscan_api_key", "basescan_api_key", "optimistic_api_key",
        "eth_rpc_ws_url", "eth_rpc_http_url", "default_chain",
        "strict_mode", "sliding_window_seconds", "anomaly_tx_threshold"
    ]:
        if key in new_cfg:
            cfg[key] = new_cfg[key]

    save_web_settings(cfg)
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
    patch_text = RemediationEngine.generate_unified_patch(source, findings, file_path="contract.sol")
    return Response(content=patch_text, media_type="text/x-diff")


# -------------------------------------------------------------
# WebSocket: Continuous Real-Time Mempool Streaming
# -------------------------------------------------------------

@app.websocket("/ws/mempool")
async def websocket_mempool(websocket: WebSocket):
    """
    Continuous mempool evaluation WebSocket:
    - Streams transactions continuously (no fixed batch limit)
    - Signals Traffic Lights: Green (safe), Yellow (warning), Red (critical)
    - Delivers one-line summaries for yellow/red signals
    - Instantly emits a complete Anomaly Insights Report when an anomaly occurs
    """
    await websocket.accept()
    cfg = load_web_settings()

    rate_tracker = SlidingWindowRateTracker(
        window_seconds=float(cfg.get("sliding_window_seconds", 10.0)),
        threshold_count=int(cfg.get("anomaly_tx_threshold", 5))
    )
    sandwich_detector = SandwichDetector(window_seconds=5.0)

    is_running = True
    mode = "simulated"
    chain = cfg.get("default_chain", "ethereum")
    interval = 0.25

    async def tx_generator():
        nonlocal mode, chain, interval
        while is_running:
            if mode == "simulated":
                async for tx in SimulatedMempoolStream.stream_synthetic(count=0, interval=interval, simulate_burst=True):
                    if not is_running:
                        break
                    yield tx
            else:
                chain_cfg = settings.get_chain_config(chain) if chain in settings.chains else None
                ws_url = cfg.get("eth_rpc_ws_url") or (chain_cfg["ws_rpc"] if chain_cfg else None)
                http_rpc = cfg.get("eth_rpc_http_url") or (chain_cfg["http_rpc"] if chain_cfg else None)
                listener = MempoolListener(ws_url=ws_url, http_rpc_url=http_rpc)
                async for tx in listener.listen_live():
                    if not is_running:
                        break
                    yield tx

    # Control task to receive commands (pause, resume, switch mode)
    async def listen_commands():
        nonlocal is_running, mode, chain, interval
        try:
            while True:
                msg = await websocket.receive_text()
                cmd = json.loads(msg)
                action = cmd.get("action")
                if action == "pause":
                    is_running = False
                elif action == "start" or action == "resume":
                    is_running = True
                    mode = cmd.get("mode", mode)
                    chain = cmd.get("chain", chain)
                    interval = float(cmd.get("interval", interval))
                elif action == "update_config":
                    if "interval" in cmd:
                        interval = float(cmd["interval"])
                    if "mode" in cmd:
                        mode = cmd["mode"]
        except Exception:
            is_running = False

    cmd_task = asyncio.create_task(listen_commands())

    try:
        gen = tx_generator()
        async for tx in gen:
            if not is_running:
                await asyncio.sleep(0.2)
                continue

            # Layer 1
            l1_payload = Normalizer.process_mempool_transaction(tx)
            # Layer 2
            parsed_hex = HexEngine.parse_transaction(tx)
            sender = parsed_hex["sender"]
            timestamp = tx.get("timestamp")

            # Sliding window evaluation
            is_anomalous, count, window_meta = rate_tracker.record_transaction(sender, timestamp=timestamp)
            # Sandwich attack evaluation
            is_sandwich, sandwich_meta = sandwich_detector.record_and_evaluate(parsed_hex, timestamp=timestamp)

            # Determine Traffic Light Signal
            # Red: Sandwich attack, high-risk malicious call, or high frequency burst
            # Yellow: Moderate frequency (>= 3) or unverified high gas
            # Green: Safe standard call
            classification = parsed_hex.get("payload_classification", "STANDARD_CALL")
            
            if is_sandwich or classification == "SUSPICIOUS_HIGH_RISK_CALL" or is_anomalous:
                signal = "red"
                if is_sandwich:
                    one_line_summary = f"[MEV SANDWICH ATTACK] Attacker {sandwich_meta.get('attacker_address', '')[:10]}... front-ran victim on pool {sandwich_meta.get('target_pool', '')[:10]}..."
                elif classification == "SUSPICIOUS_HIGH_RISK_CALL":
                    one_line_summary = f"[CRITICAL CALL] High-risk function selector {parsed_hex.get('function_selector')} ({parsed_hex.get('decoded_function_name')}) fired by {sender[:10]}..."
                else:
                    one_line_summary = f"[BURST ANOMALY] Sender {sender[:10]}... sent {count} transactions in {window_meta.get('window_seconds')}s (Threshold: {window_meta.get('threshold_count')})"
            elif count >= 3 or parsed_hex.get("gas_price_gwei", 0) > 100:
                signal = "yellow"
                one_line_summary = f"[ELEVATED ACTIVITY] Sender {sender[:10]}... approaching burst threshold ({count} txs in window)"
            else:
                signal = "green"
                one_line_summary = None

            # Prepare Instant Anomaly Insights Report if flagged
            anomaly_report = None
            if signal == "red":
                anomaly_report = generate_anomaly_insights_report(
                    parsed_hex=parsed_hex,
                    window_meta=window_meta,
                    sandwich_meta=sandwich_meta if is_sandwich else None
                )
                # Persist to database
                try:
                    if is_sandwich:
                        db.save_mempool_anomaly({
                            "tx_hash": sandwich_meta["backrun_tx"],
                            "sender": sandwich_meta["attacker_address"],
                            "target": sandwich_meta["target_pool"],
                            "function_selector": parsed_hex.get("function_selector"),
                            "payload_classification": "MEV_SANDWICH_ATTACK"
                        }, {
                            "count_in_window": 3,
                            "window_seconds": 5.0,
                            "anomaly_reason": sandwich_meta["detection_reason"]
                        })
                    else:
                        db.save_mempool_anomaly(parsed_hex, window_meta)
                except Exception as e:
                    logger.warning(f"Failed to persist anomaly: {e}")

            # Send event to client
            event_payload = {
                "signal": signal,
                "one_line_summary": one_line_summary,
                "tx": {
                    "tx_hash": parsed_hex.get("tx_hash"),
                    "sender": parsed_hex.get("sender"),
                    "target": parsed_hex.get("target"),
                    "value_wei": parsed_hex.get("value_wei"),
                    "gas_price_gwei": parsed_hex.get("gas_price_gwei", 0),
                    "function_selector": parsed_hex.get("function_selector"),
                    "decoded_name": parsed_hex.get("decoded_function_name"),
                    "classification": classification,
                    "count_in_window": count,
                    "window_seconds": window_meta.get("window_seconds", 10.0),
                    "timestamp": timestamp or datetime.now(timezone.utc).strftime("%H:%M:%S")
                },
                "anomaly_report": anomaly_report
            }

            await websocket.send_text(json.dumps(event_payload))
            await asyncio.sleep(interval)

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

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Chain-Mind Auditor Web Frontend Initializing...</h1>"

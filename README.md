# Chain-Mind Auditor

**Chain-Mind Auditor** is an enterprise-grade, end-to-end blockchain security auditing, mempool monitoring, and threat ingestion platform. It ingests live EVM network data (real-time pending mempool transactions and verified contract source code across multiple explorers), defends against adversarial inputs and prompt injection attacks, executes deterministic algorithmic threat detection alongside generative AI reasoning, and provides automated vulnerability remediation.

---

## Architecture Overview

The system follows a resilient **3-Tier Pipeline**:

```
[ 1. INGESTION & DEFENSE LAYER ]
 ├── Mode A: Mempool Stream (WebSockets -> Live wss:// or High-Fidelity Simulation)
 ├── Mode B: Multi-Chain Explorer Client (Etherscan, Arbiscan, Polygonscan, Basescan, Optimism)
 ├── Defensive Sanitizer: Regex comment stripper, Zero-width character & XML tag jailbreak defense
 └── Token Bucket Rate Limiter (<= 5 req/s) & FIFO backpressure buffer queue
        │
[ 2. DUAL-PATH PROCESSING & ANALYSIS LAYER ]
 ├── Pathway A (Deterministic Algorithms & DSA):
 │    ├── Hex Engine: 4-byte function selector decoding, calldata parameter unpacking, dangerous call flagging
 │    ├── DSA Sliding Window (Deque): O(1) timestamp-based sender velocity & burst anomaly detection
 │    ├── MEV Sandwich Detector: Front-run, victim, and back-run transaction pattern classification
 │    └── Heuristic Engine: Deep static vulnerability analyzer (Reentrancy, tx.origin, uninitialized proxies, etc.)
 ├── Pathway B (GenAI Security Pipeline):
 │    ├── Strict Context Isolation: Defensive XML tagging (<smart_contract_source_code>)
 │    ├── Structured Reasoning: 4-Domain EVM security evaluation (State/Control, Financial Invariants, Governance, Network)
 │    └── Resilient Guardrails: Pydantic schema validation + regex self-healing JSON repair
 └── Remediation Engine: Auto-generates unified .patch diffs and safe contract refactors
        │
[ 3. PRESENTATION & WORKSPACE LAYER ]
 ├── Web Operations Center: Modern FastAPI + WebSocket dashboard (http://127.0.0.1:5000)
 ├── Interactive Terminal CLI Menu: Full keyboard-navigable security operations console
 ├── Enterprise Export Formats: OASIS SARIF v2.1.0 (GitHub Code Scanning) & Standalone Interactive HTML Reports
 ├── Persistent Audit Trail: SQLite with WAL (Write-Ahead Logging) and priority-based age retention
 └── CI/CD Quality Gate: --fail-on-risk <threshold> exit-code gating for automated deployment pipelines
```

---

## Core Features & Capabilities

### 1. Smart Contract Security Auditing
- **Multi-Input Ingestion**: Audit local `.sol` files, entire project folders, raw pasted Solidity code, or live verified on-chain addresses.
- **Multi-Chain Support**: Native explorer integration with **Ethereum, Arbitrum, Optimism, Polygon, and Base**.
- **Multi-File Unpacker**: Flattens nested, multi-file and stringified JSON compiler outputs into a unified dependency tree.
- **Dual-Engine Security Analysis**:
  - **GenAI Reasoning**: Uses Google Gemini to detect complex business logic bugs, economic edge-cases, and reentrancy variations.
  - **Offline Heuristic Engine**: Zero-dependency static analysis detecting timestamp dependence, missing zero-address checks, unchecked return values, unprotected proxy initializers, pre-0.8.0 integer overflows, and dangerous authorization patterns.
- **Four Standard Security Domains**:
  1. *EVM State & Control Flow Integrity*
  2. *Business Logic & Financial Invariants*
  3. *Setup, Upgradeability & Governance*
  4. *Real-Time Network Mechanics & Mempool Telemetry*

### 2. Real-Time Mempool Monitoring & MEV Detection
- **Dual Stream Modes**:
  - **Live Mode**: Connects directly to Ethereum nodes via WebSockets (`wss://`).
  - **Simulated Mode**: Built-in realistic attack simulation reproducing flash-loan attacks, DDoS bursts, and drain exploits.
- **Algorithmic Hex Engine**: Extracts 4-byte function selectors (`0x` + 8 hex characters), decodes standard signatures (ERC-20, DEX swaps, approvals), and flags high-risk calls (`selfdestruct`, emergency withdrawals).
- **DSA Sliding Window Anomaly Detection**: Uses in-memory double-ended queues (`collections.deque`) with amortized $O(1)$ eviction to detect abnormal transaction velocity and bot bursts within moving time windows (e.g., 10s).
- **Sandwich Attack Identification**: Analyzes transaction sequences to flag front-running high gas fees, victim transactions, and back-running profit drains.
- **EIP-1559 Gas Spike Detection**: Flags priority fee anomalies and aggressive gas bidding.

### 3. Adversarial Defense & Guardrails
- **Prompt Injection Defense**: Neutralizes jailbreaks hidden in comments or docstrings (e.g., `"IGNORE ALL RULES"`, `"RETURN RISK 0"`).
- **Evasion Neutralization**: Strips zero-width unicode characters and nested XML injection tags.
- **Self-Healing Output Guardrails**: Automatically detects and repairs common LLM syntax failures (markdown code fences, conversational fluff, single-quoted JSON, Python `True`/`False` literals).

### 4. Remediation & Enterprise CI/CD
- **Automated Fix Generation**: Generates diff patches (`.patch`) for detected vulnerabilities and produces full refactored secure Solidity contracts.
- **OASIS SARIF v2.1.0 Exporter**: Directly integrates with **GitHub Advanced Security** and IDE security scanning tabs.
- **Standalone HTML Audit Reports**: Generates interactive, self-contained HTML audit reports with color-coded severity badges and remediation instructions.
- **CI/CD Quality Gate**: Command-line flag `--fail-on-risk <score>` that automatically fails builds (exit code `1`) if high-severity vulnerabilities are present.

### 5. Web Operations Center & REST API
- **Modern Web Dashboard**: Served directly on `http://127.0.0.1:5000` with 5 workspaces:
  - **Overview**: High-level platform telemetry, readiness metrics, and recent security events.
  - **Contract Audit**: Interactive contract submission, multi-file relationship mapping, and remediation viewer.
  - **Mempool Monitor**: Real-time dark terminal transaction feed with signal filtering and pause controls.
  - **Audit History**: Searchable, paginated audit records and anomaly logs.
  - **Settings**: Authenticated management of API keys, RPC endpoints, and pipeline toggles.
- **Interactive OpenAPI Docs**: Complete Swagger UI documentation available at `/docs`.

### 6. Storage & Data Retention
- **SQLite Database with WAL Mode**: High-throughput persistence for audit logs and mempool anomalies.
- **Smart Priority Retention**: Automatically purges stale low-priority records (P3) while permanently safeguarding critical security findings (P1).

---

## Quickstart & Navigation Guide

For new users, we provide a unified shortcut launcher to explore and run the 3 core modes of Chain-Mind Auditor easily:

### 1. Interactive Shortcut Menu
Double-click `quickstart.bat` on Windows or run:
```bash
python quickstart.py
```
This presents an interactive menu explaining the 3 available run modes:
- **Mode 1 — [Web] Web Operations Center**: Launch FastAPI browser dashboard & API docs at `http://127.0.0.1:5000`
- **Mode 2 — [CLI] Terminal CLI Menu**: Interactive contract auditor, mempool analyzer, and history viewer
- **Mode 3 — [Test] Automated Test Suite**: Run the complete 51+ test suite across ingestion, heuristics, guardrails, & web APIs

### 2. Automatic Non-Interactive Execution
Run without prompts or user intervention directly from shell or scripts:
```bash
# Auto-launch Web Operations Center directly
python quickstart.py --auto

# Or specify a target mode directly
python quickstart.py --mode web
python quickstart.py --mode menu
python quickstart.py --mode tests
```

### 3. Programmatic Python Function Callers
You can also import and trigger auto-runners directly in Python:
```python
from quickstart import auto_run, auto_run_web, auto_run_menu, auto_run_tests

# Auto-launch web dashboard programmatically
auto_run_web(port=5000)

# Or run by mode name
auto_run(mode="web")
```

---

## Getting Started & Installation

### Prerequisites
- Python 3.12+

### Setup
```bash
# Clone the repository
git clone https://github.com/AnkanMandal-god/Chain_Audit.git
cd Chain_Audit

# Create and activate virtual environment
python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Windows (CMD):
.\.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## CLI Commands & Scripting Reference

### 1. Audit Smart Contracts
```bash
# Terminal Dashboard view (Rich UI)
python main.py audit-contract data/test_contracts/VulnerableVault.sol

# Clean Safe Contract
python main.py audit-contract data/test_contracts/SafeERC20.sol

# Export audit report directly to JSON file
python main.py audit-contract data/test_contracts/VulnerableVault.sol --output report.json

# Export standalone interactive HTML report
python main.py audit-contract data/test_contracts/VulnerableVault.sol --html-report audit.html

# Export SARIF v2.1.0 for GitHub Security tab
python main.py audit-contract data/test_contracts/VulnerableVault.sol --sarif results.sarif

# Save unified remediation diff patch
python main.py audit-contract data/test_contracts/VulnerableVault.sol --patch-output fix.patch

# CI/CD Quality Gate (exit code 1 if risk score >= 70)
python main.py audit-contract data/test_contracts/VulnerableVault.sol --fail-on-risk 70

# Batch audit an entire directory of contracts
python main.py audit-directory data/test_contracts

# Audit verified contract from Etherscan
python main.py audit-contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 --chain ethereum
```

### 2. Stream Mempool Transactions
```bash
# Run high-fidelity simulation with burst attack scenarios:
python main.py stream-mempool --count 25 --interval 0.1

# Configure custom sliding window and anomaly threshold:
python main.py stream-mempool --window 10.0 --threshold 5

# Connect to live Ethereum RPC WebSocket (requires endpoint):
python main.py stream-mempool --live
```

### 3. View Persisted History (SQLite)
```bash
# View recent smart contract audit history:
python main.py view-history

# View recent mempool anomaly alerts:
python main.py view-history --anomalies
```

---

## Web Workspace & REST API Reference

The Web Operations Center runs on `http://127.0.0.1:5000` (`python main.py web --port 5000`).

### Web API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Engine mode, chain, and capability readiness matrix |
| `GET` | `/api/overview` | Recent activity, aggregate records, and system health |
| `GET` | `/api/demo/samples` | Local sample contracts and test suites |
| `POST` | `/api/audit/contract` | Audit source code, file target, or explorer address |
| `POST` | `/api/audit/detect-relationships` | Analyze dependencies & imports in supplied sources |
| `POST` | `/api/audit/batch` | Audit a connected set of source files |
| `GET` | `/api/history/audits` | Paginated, searchable contract audit history |
| `GET` | `/api/history/anomalies` | Paginated, searchable mempool anomaly alerts |
| `POST` | `/api/settings/verify-auth` | Verify admin settings passcode |
| `GET/POST`| `/api/settings/load`, `/api/settings/save` | Read masked settings or save configuration |
| `POST` | `/api/export/html`, `/api/export/sarif`, `/api/export/patch` | Export current report to HTML, SARIF, or Diff Patch |
| `WebSocket` | `/ws/mempool` | Real-time simulated or live pending transaction stream |

### Configuration & Settings

The Settings area is protected by the `admin_passcode` (default: `chainmind-admin`).

| Setting | Purpose |
| :--- | :--- |
| `GEMINI_API_KEY` | Enables GenAI audit path (required for Strict Real Mode) |
| `ETHERSCAN_API_KEY` | Etherscan verified source ingestion key |
| `ARBISCAN_API_KEY` / `POLYGONSCAN_API_KEY` | Layer-2 explorer API keys |
| `ETHEREUM_WS_RPC` | WebSocket endpoint for live mempool monitoring (`wss://...`) |
| `ETHEREUM_HTTP_RPC` | HTTP JSON-RPC fallback provider |
| `Strict Real Mode` | Disables heuristic fallback; enforces exact API/LLM responses |
| `Sliding Window Seconds` | Frequency analysis time window (1–300s, default: 10s) |
| `Anomaly Threshold` | Transactions in window required to trigger anomaly (default: 5) |

---

## Test Suite & Verification

The codebase includes a **comprehensive 51-test automated test suite** running on `pytest`:

```bash
python main.py run-tests
# OR: pytest -v tests
```

### Verified Test Matrix:
- **Safe Comment Stripping & String Preservation**: Handles inline strings, multi-line blocks, and NatSpec tags.
- **Prompt Injection & Adversarial Neutralization**: Tests zero-width evasions, XML tag breakouts, and prompt leaks.
- **Etherscan Multi-File Ingestion**: Unpacks nested compiler JSON bundles and extracts AST signatures.
- **Token Bucket Rate Limiting**: Verifies $<=\text{5 req/sec}$ timing accuracy and backpressure queues.
- **DSA Sliding Window Anomaly Detection**: Validates $O(1)$ deque eviction, burst detection, and garbage collection.
- **Hex Engine & ABI Decoding**: Selectors for ERC-20 transfers, infinite approvals, and high-risk drains.
- **MEV Sandwich Detection**: Verifies front-run / victim / back-run transaction sequence classification.
- **Static Heuristics Engine**: Reentrancy, `tx.origin` patterns, transient storage (`TSTORE`), uninitialized proxies, and pre-0.8.0 overflows.
- **Pydantic Guardrails & Self-Healing**: Repairs markdown fences, single-quoted JSON, and python literals.
- **SARIF & HTML Export**: Conformance with OASIS SARIF v2.1.0 and interactive HTML report generation.
- **SQLite Persistence & WAL Mode**: Validates ACID compliance, indexes, and priority-based age retention.
- **Web REST & WebSocket APIs**: Endpoints, relationship detector, and auth gate testing.

**Result: 51 / 51 tests passed (100% pass rate).**

---

## License

This project is licensed under the MIT License.

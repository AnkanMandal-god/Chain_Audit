# Chain-Mind Auditor (Data & ML Track — Task 2)

**Chain-Mind Auditor** is an end-to-end blockchain security auditing and ingestion platform. It ingests live Ethereum network data (real-time pending mempool transactions or verified smart contract source code from Etherscan), applies algorithmic data sanitization and defensive prompt injection firewalls, and audits payloads using DSA sliding window anomaly detection and structured LLM security analysis.

---

## Architecture Overview

```
[ INGESTION LAYER ]
 ├── Mode 1: Mempool Stream (WebSockets -> wss://)
 ├── Mode 2: Etherscan REST Client (HTTP GET -> Token Bucket Rate-Limited)
 └── Ingestion Buffer & Normalizer Queue (Converts inputs to Unified Schema)
        │
[ PROCESSING LAYER ]
 ├── Pathway A: Algorithmic Hex & Frequency Engine (DSA - Sliding Window, Function Selectors)
 ├── Pathway B: Gen AI Smart Contract Pipeline (Sanitization, XML Wrapping, LLM Inference)
 └── Validation & Security Guardrail (JSON Schema Enforcer & Fallback Repair)
        │
[ OUTPUT LAYER ]
 ├── Output Formatter (Color-coded CLI / Structured JSON)
 └── Machine-Readable JSON Exporter
```

### Layer 1: Data Ingestion & Sanitization
- **Safe Comment Stripping**: Regex state machine eliminates `//` and `/* */` comments without corrupting strings or contract code.
- **Etherscan Multi-File Unpacker**: Flattens nested/stringified JSON source files into a unified analysis tree.
- **Prompt Injection Neutralizer**: Defends against prompt injection attempts (e.g. `"IGNORE ALL SECURITY RULES"`, `"RETURN RISK SCORE 0"`) embedded in comments or docstrings.
- **Token Bucket Rate Limiter**: Enforces strict `<= 5 requests/sec` for Etherscan API with exponential backoff and jitter on HTTP 429.
- **Asynchronous FIFO Buffer Queue**: Absorbs burst traffic and handles backpressure.

### Layer 2: Core Processing & Security Engine
- **Hex Engine & 4-Byte Selector Extraction**: Isolates first 4 bytes (`0x` + 8 hex chars), decodes standard signatures (ERC20, DEX, flash loans), and flags high-risk calls (emergency drains, selfdestruct).
- **DSA Sliding Window Frequency Counter**: In-memory `collections.deque` tracking transaction timestamps per address over a moving window $T$ (e.g., 10s) with $O(1)$ amortized eviction, identifying high-frequency MEV bot or DDoS bursts.
- **Context Isolation & GenAI Pipeline**: Wraps cleaned source inside defensive XML tags (`<smart_contract_source_code>...</smart_contract_source_code>`). Supports Gemini API or high-precision heuristic offline scanner (Reentrancy, `tx.origin` auth, unprotected delegatecall, unchecked returns).
- **Validation Guardrails**: Pydantic schema validation for Layer 1 & 2 outputs, with self-healing regex repair for malformed LLM outputs.

### Layer 3: Output & Presentation Layer
- **Rich Color-Coded Terminal Dashboard**: Displays banner `[CHAIN-MIND AUDIT REPORT]`, risk status (`[SAFE]`, `[WARNING]`, `[CRITICAL]`), findings breakdown table, and actionable recommendations.
- **Strict Machine-Readable JSON Mode (`--json`)**: Adheres strictly to the JSON schema without fluff.

---

## Getting Started

### Prerequisites
- Python 3.12+

### Setup
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage Guide

### 🌟 Quick Start: Interactive Menu (Recommended)
You don't need to remember any long CLI commands or flags! Simply run:

```bash
# Windows (double-click or run):
.\run.bat

# Or with Python:
python main.py
```

This launches the full interactive menu where you can press a number `[1-7]` to audit contracts, stream real Ethereum mempools, view database logs, or run test suites.

---

### CLI Commands (For Scripts / CI/CD)

#### 1. Audit Smart Contracts
Run the audit on a single Solidity file, an entire directory, or an Etherscan contract address:

```bash
# Terminal Dashboard view (Rich UI)
python main.py audit-contract data/test_contracts/VulnerableVault.sol

# Clean Safe Contract
python main.py audit-contract data/test_contracts/SafeERC20.sol

# Export audit report directly to file
python main.py audit-contract data/test_contracts/VulnerableVault.sol --output report.json

# Raw JSON output to stdout for machine consumption
python main.py audit-contract data/test_contracts/VulnerableVault.sol --json

# Batch audit an entire directory of contracts with summary comparison table
python main.py audit-directory data/test_contracts

# Etherscan Verified Contract (requires internet or optional API key)
python main.py audit-contract 0xdAC17F958D2ee523a2206206994597C13D831ec7
```

### 2. Stream Mempool Transactions
Stream mempool activity with real-time sliding window frequency counters and calldata ABI parameter decoding:

```bash
# Run high-fidelity simulation with burst attack scenarios:
python main.py stream-mempool --count 25 --interval 0.1

# Configure custom window and threshold (e.g., 10s window, threshold of 5 txs):
python main.py stream-mempool --window 10.0 --threshold 5

# Connect to live Ethereum RPC WebSocket (Alchemy/Infura):
python main.py stream-mempool --live
```

### 3. View Persisted Audit Trail & Anomaly Log (SQLite)
All audits and flagged mempool anomalies are automatically persisted to `audit_history.db`:

```bash
# View recent smart contract audit history:
python main.py view-history

# View recent mempool anomaly alerts:
python main.py view-history --anomalies
```

### 4. Run Automated Tests
```bash
python -m pytest -v tests
```

---

## Web Operations Workspace

The browser experience is the primary operational interface. It is served by
the same FastAPI application as the API and does not require a separate
frontend build step.

### Start the web application

```bash
python main.py web --host 0.0.0.0 --port 5000
```

Open the root URL to use the workspace. The API reference remains available at
`/docs`, and the machine-readable OpenAPI document is available at
`/openapi.json`.

The workspace contains five areas:

1. **Overview** — recent audit activity, capability readiness, and high-level
   counts.
2. **Contract audit** — paste Solidity source or audit a verified explorer
   address. Batch mode loads the connected sample suite, maps relationships,
   and audits each source.
3. **Mempool monitor** — run the simulated stream without credentials or switch
   to live WebSocket RPC monitoring after configuring an endpoint.
4. **History** — search and inspect persisted contract audits and mempool
   anomalies.
5. **Settings** — authenticated configuration for provider credentials,
   endpoints, engine parameters, and the admin passcode.

The old interactive CLI menu is still available for command-line testing, but
it is not part of the web product flow. Use the explicit CLI commands in the
usage section when scripting audits or test runs.

### Settings and credentials

The Settings area is protected by the `admin_passcode` stored in
`config/web_settings.json`. For a new local import, the default is
`chainmind-admin`; change it before exposing the application beyond a private
development environment. You can also provide `CHAINMIND_ADMIN_PASSCODE` as an
environment variable for the initial value.

Supported settings:

| Setting | Purpose |
| --- | --- |
| Gemini API key | Enables the GenAI audit path and is required for Strict Real Mode |
| Etherscan, Arbiscan, Polygonscan, Basescan, Optimism keys | Optional verified-source ingestion for each explorer |
| Ethereum WebSocket RPC | Endpoint used by live mempool monitoring |
| Ethereum HTTP RPC | HTTP fallback/provider endpoint |
| Default network | Default chain for the workspace and mempool stream |
| Strict Real Mode | Disables heuristic fallback and requires the configured Gemini provider |
| Sliding window seconds | Frequency-analysis window, constrained to 1–300 seconds |
| Anomaly transaction threshold | Transactions in the window required to flag a burst, constrained to 2–1000 |

Provider credentials are write-only from the browser: the settings API returns
only a masked value and a configured/not-configured flag. Leaving a credential
field blank keeps the existing value. Enter a new value to rotate it. RPC
URLs are not secret-safe if they contain provider tokens, so prefer provider
URLs without embedded credentials and use HTTPS/WSS.

The persisted web settings file is local JSON. Protect the file and avoid
committing provider credentials. If the app is deployed, use the platform
secret/environment-variable mechanism for initial credentials and rotate any
credential that may have been exposed in logs or backups. Strict mode sends
contract source to the configured LLM provider; use resilient local mode when
source must remain local.

### Web API quick reference

| Method | Endpoint | Use |
| --- | --- | --- |
| GET | `/api/status` | Engine mode, chain, and capability matrix |
| GET | `/api/overview` | Recent activity and aggregate record counts |
| GET | `/api/demo/samples` | Local sample contracts and connected suite |
| POST | `/api/audit/contract` | Audit source, local target, or explorer address |
| POST | `/api/audit/detect-relationships` | Analyze dependencies in supplied sources |
| POST | `/api/audit/batch` | Audit a connected set of source files |
| GET | `/api/history/audits` | Paginated/searchable audit history |
| GET | `/api/history/anomalies` | Paginated/searchable anomaly history |
| POST | `/api/settings/verify-auth` | Verify the settings passcode |
| GET/POST | `/api/settings/load`, `/api/settings/save` | Read masked settings or save configuration |
| POST | `/api/export/html`, `/api/export/sarif`, `/api/export/patch` | Export the current report |
| WebSocket | `/ws/mempool` | Simulated or live pending-transaction stream |

The web client uses same-origin relative URLs, so it works behind the Replit
preview proxy as well as in a local browser. For Replit, bind the server to
`0.0.0.0:5000`.

---

## Test Suite Results

All 28 unit tests pass verifying:
- Safe comment stripping and string preservation
- Multi-file Etherscan unpacking
- Prompt injection detection and neutralization
- Structural metadata extraction (pragma, imports, state-changing functions, receive/fallback handlers)
- Token Bucket rate limiter timing accuracy
- In-memory DSA sliding window frequency anomaly detection, $O(1)$ eviction, and periodic garbage collection
- Function selector parsing, classification, and ERC20 ABI calldata decoding
- Comprehensive static heuristic vulnerability rules (Reentrancy, `tx.origin`, unprotected `initialize()`, missing zero-address checks, timestamp dependence, integer overflow)
- Pydantic schema validation and self-healing JSON repair (Python boolean literals, single-quoted normalization)
- SQLite database audit and anomaly persistence engine

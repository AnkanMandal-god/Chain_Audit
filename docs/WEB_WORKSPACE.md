# Chain-Mind web workspace

The web workspace is served by the existing FastAPI application:

```bash
python main.py web --host 0.0.0.0 --port 5000
```

## Contract audit

The Contract audit view accepts pasted Solidity, individual `.sol` files,
folders, verified explorer addresses, or the connected sample suite.

The audit pipeline follows the attached Chain-Mind security framework:

1. **Ingestion** — multi-file unpacking, safe comment stripping, prompt
   neutralization, structural metadata extraction, and schema checks.
2. **Deterministic analysis** — selector decoding, calldata classification,
   sliding-window transaction velocity, and the offline Solidity heuristic
   engine.
3. **LLM analysis** — optional XML-isolated Gemini reasoning with JSON schema
   validation and resilient heuristic fallback.
4. **Four security domains** — EVM state/control flow; business logic,
   financial invariants/inputs; setup, upgradeability/governance; and
   real-time network mechanics/mempool telemetry.
5. **Severity actions** — `CRITICAL` is an immediate alert, `WARNING` is
   manual-review material, and `SAFE` passes the configured checks.

After an audit, the **Generate secure contract** action is shown only when
findings exist. With Gemini configured it asks the LLM for a full revised
contract while preserving the interface where possible. Without Gemini it
uses a conservative offline baseline for common findings such as
`tx.origin`, unchecked calls, and reentrancy. Generated Solidity must always
be compiled, tested, and reviewed before deployment.

## Mempool monitor

The monitor uses a dark terminal-style feed for pending transactions. Each
row is evaluated for:

- dangerous function selectors and privileged calls;
- sender velocity using an O(1)-amortized deque sliding window;
- priority-fee / gas spikes;
- unlimited approvals and large transfers;
- sandwich topology using front-run, victim, and back-run ordering.

The terminal supports signal filtering, auto-scroll locking, clearing the
feed, row inspection, and live anomaly details. It requires a working WSS RPC
endpoint for real network data; the UI reports connection errors explicitly
instead of fabricating live results.

## History and retention

Audit and anomaly records are stored in SQLite. History displays a priority
badge:

- **P1 critical** — destructive calls, sandwich attacks, high-frequency bursts,
  and critical contract findings;
- **P2 review** — upgrades, approvals, gas spikes, and medium-risk findings;
- **P3 routine** — safe or low-risk records.

On startup, history access, and settings save, the retention job deletes stale
low-priority records first. If a table exceeds its configured maximum, it
deletes the lowest-priority, oldest records first. Critical/high-risk records
are protected from the normal age cleanup.

## Settings

Settings are admin-protected and secrets are masked after saving. In addition
to provider credentials and RPC endpoints, the following pipeline controls are
editable:

- strict real mode;
- offline heuristic engine;
- LLM reasoning engine;
- selector analysis;
- frequency/sliding-window analysis;
- sandwich detection;
- prompt neutralization;
- sliding-window duration and anomaly threshold;
- history retention days and per-table record cap.

The local development configuration starts in resilient mode so audits work
without a Gemini key. Set `CHAINMIND_ADMIN_PASSCODE` or change the passcode in
Settings before exposing the app publicly.
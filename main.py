"""
Chain-Mind Auditor: Unified Terminal CLI & System Runner.

Commands:
- audit-contract <path-or-address> [--json] [--output file.json]
- audit-directory <dir-path>
- stream-mempool [--live] [--count N] [--interval S]
- view-history [--anomalies]
- run-tests
"""
import sys
import os
import json
import asyncio
import argparse
from pathlib import Path

# Auto-detect and switch to local .venv if httpx is missing in current Python
try:
    import httpx
except ModuleNotFoundError:
    venv_python = Path(__file__).resolve().parent / ".venv" / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python")
    if venv_python.exists() and Path(sys.executable).resolve() != venv_python.resolve():
        import subprocess
        result = subprocess.run([str(venv_python), str(Path(__file__).resolve())] + sys.argv[1:])
        sys.exit(result.returncode)
    else:
        print("\n[!] Error: Required dependencies are not installed in your active Python environment.")
        print(f"    Current Python: {sys.executable}")
        print("    Please run: pip install -r requirements.txt\n")
        sys.exit(1)

from config.settings import settings
from src.pipeline import ChainMindPipeline
from src.presentation.db_storage import AuditDatabase
from src.presentation.html_reporter import HTMLReporter
from src.presentation.sarif_exporter import SARIFExporter
from src.presentation.remediation_engine import RemediationEngine
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console(safe_box=True)

# Expose FastAPI app instance for Vercel / ASGI serverless runners
try:
    from src.web.server import app
except Exception:
    app = None



def parse_args():
    parser = argparse.ArgumentParser(
        description="Chain-Mind Auditor: Intelligent Blockchain Ingestion & Security Auditing Platform"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: menu
    subparsers.add_parser("menu", help="Launch interactive menu system")

    # Command: audit-contract
    audit_parser = subparsers.add_parser("audit-contract", help="Audit smart contract source code")
    audit_parser.add_argument("target", help="Filepath to .sol contract OR 0x Ethereum address")
    audit_parser.add_argument("--json", action="store_true", help="Output strict JSON schema instead of CLI UI")
    audit_parser.add_argument("--output", default=None, help="Save JSON audit report to disk")
    audit_parser.add_argument("--html-report", default=None, help="Save standalone interactive HTML audit report to disk")
    audit_parser.add_argument("--sarif", default=None, help="Save OASIS SARIF v2.1.0 report for GitHub Security Code Scanning")
    audit_parser.add_argument("--patch-output", default=None, help="Save unified remediation diff patch to disk")
    audit_parser.add_argument("--fail-on-risk", type=int, default=None, help="CI/CD Quality Gate: exit with code 1 if risk_score >= threshold")
    audit_parser.add_argument("--chain", default="ethereum", help="Blockchain network (ethereum, arbitrum, optimism, polygon, base)")
    audit_parser.add_argument("--api-key", default=None, help="Explorer API key")
    audit_parser.add_argument("--strict", action="store_true", help="Strict Real Mode: No heuristic fallbacks or self-healing repair; raises exact API/LLM errors")

    # Command: audit-directory
    dir_parser = subparsers.add_parser("audit-directory", help="Audit all Solidity contracts in a directory")
    dir_parser.add_argument("directory", help="Path to folder containing .sol files")
    dir_parser.add_argument("--sarif", default=None, help="Save aggregated OASIS SARIF v2.1.0 report for directory")
    dir_parser.add_argument("--fail-on-risk", type=int, default=None, help="CI/CD Quality Gate: exit with code 1 if any contract risk_score >= threshold")
    dir_parser.add_argument("--chain", default="ethereum", help="Blockchain network")
    dir_parser.add_argument("--api-key", default=None, help="Explorer API key")
    dir_parser.add_argument("--strict", action="store_true", help="Strict Real Mode: No heuristic fallbacks; raises exact API/LLM errors")

    # Command: stream-mempool
    mempool_parser = subparsers.add_parser("stream-mempool", help="Stream and analyze pending mempool transactions")
    mempool_parser.add_argument("--live", action="store_true", help="Connect to live WebSocket RPC (default is simulated)")
    mempool_parser.add_argument("--count", type=int, default=25, help="Number of transactions to process (0 = infinite)")
    mempool_parser.add_argument("--interval", type=float, default=0.25, help="Interval between transactions in seconds")
    mempool_parser.add_argument("--window", type=float, default=10.0, help="Sliding window time in seconds")
    mempool_parser.add_argument("--threshold", type=int, default=5, help="Anomaly frequency threshold in window")
    mempool_parser.add_argument("--chain", default="ethereum", help="Target network for mempool RPC")

    # Command: view-history
    hist_parser = subparsers.add_parser("view-history", help="View persisted audit trail and mempool anomalies from SQLite")
    hist_parser.add_argument("--limit", type=int, default=10, help="Number of records to display")
    hist_parser.add_argument("--anomalies", action="store_true", help="View mempool anomalies instead of contract audits")

    # Command: run-tests
    subparsers.add_parser("run-tests", help="Execute automated test suite across all 3 layers")

    # Command: web
    web_parser = subparsers.add_parser("web", help="Launch interactive Web Operations Center & API server")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=8000, help="Listening port (default: 8000)")

    return parser.parse_args()


from typing import List, Optional

def display_error_panel(
    title: str,
    message: str,
    details: Optional[str] = None,
    suggestions: Optional[List[str]] = None
):
    """Renders a prominent, color-coded error box with diagnostic details and actionable fixes."""
    text = f"[bold red]{message}[/bold red]\n"
    if details:
        text += f"\n[dim white]Details: {details}[/dim white]\n"
    if suggestions:
        text += "\n[bold yellow]Suggestions & Fixes:[/bold yellow]\n"
        for s in suggestions:
            text += f" [cyan]->[/cyan] {s}\n"

    console.print()
    console.print(Panel(text.strip(), title=f"[bold red][!] {title}[/bold red]", border_style="red", safe_box=True))
    console.print()


async def run_audit(
    target: str,
    raw_json: bool,
    output_file: str = None,
    html_report_path: str = None,
    sarif_report_path: str = None,
    patch_output_path: str = None,
    fail_on_risk: int = None,
    chain: str = "ethereum",
    api_key: str = None,
    strict: bool = False
):
    pipeline = ChainMindPipeline(etherscan_api_key=api_key, chain=chain, strict_mode=strict)
    target_path = Path(target)
    result = None

    try:
        if target_path.is_file():
            if not raw_json:
                console.print(f"[bold cyan]Reading local smart contract from:[/bold cyan] {target}")
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    raw_source = f.read()
            except UnicodeDecodeError:
                with open(target_path, "r", encoding="latin-1") as f:
                    raw_source = f.read()

            if not raw_source.strip():
                display_error_panel(
                    title="Empty Contract File",
                    message=f"The file '{target}' is empty (0 bytes of code).",
                    suggestions=["Ensure the file contains valid Solidity smart contract source code."]
                )
                return

            result = await pipeline.audit_smart_contract_source(
                raw_source=raw_source,
                target_address=f"LocalFile::{target_path.name}",
                raw_json_output=raw_json
            )
        elif target.startswith("0x"):
            if len(target) != 42:
                display_error_panel(
                    title="Invalid Ethereum Address Length",
                    message=f"Target '{target}' has length {len(target)} (expected 42 characters).",
                    suggestions=[
                        "Ethereum addresses must be exactly 42 characters including '0x'.",
                        "Example: 0xdAC17F958D2ee523a2206206994597C13D831ec7"
                    ]
                )
                return

            if not raw_json:
                console.print(f"[bold cyan]Fetching verified contract from {chain.capitalize()} Explorer:[/bold cyan] {target}")
            result = await pipeline.audit_etherscan_contract(target, raw_json_output=raw_json)

            if result.get("status") == "ERROR":
                display_error_panel(
                    title="Etherscan Contract Ingestion Failed",
                    message=f"Could not retrieve verified source for contract {target}.",
                    details=result.get("error"),
                    suggestions=[
                        f"Verify that the contract is deployed on {chain.capitalize()}.",
                        "Ensure the contract is verified on the explorer (unverified contracts only have raw bytecode).",
                        "If experiencing rate-limiting, pass an API key: --api-key YOUR_KEY",
                        "If api.etherscan.io is blocked by your network/firewall, save the .sol file locally and audit it directly."
                    ]
                )
                return
        else:
            display_error_panel(
                title="Invalid Audit Target",
                message=f"'{target}' is neither an existing file nor a valid 42-char hex address.",
                suggestions=[
                    "Check the file path for typos (e.g. data/test_contracts/VulnerableVault.sol).",
                    "If specifying an Ethereum contract address, make sure it begins with '0x' and is 42 hex characters."
                ]
            )
            return

    except Exception as exc:
        display_error_panel(
            title="Audit Execution Failed",
            message=f"An unexpected error occurred while auditing target '{target}'.",
            details=str(exc),
            suggestions=[
                "Check that the input contract is well-formed Solidity.",
                "Verify file read permissions."
            ]
        )
        return

    if output_file and result:
        try:
            out_path = Path(output_file)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            if not raw_json:
                console.print(f"[bold green]JSON audit report exported to:[/bold green] {output_file}")
        except Exception as e:
            display_error_panel(
                title="JSON Export Error",
                message=f"Could not write JSON report to '{output_file}'.",
                details=str(e)
            )

    if html_report_path and result:
        try:
            HTMLReporter.save_html_report(result, html_report_path)
            if not raw_json:
                console.print(f"[bold green]Interactive HTML report exported to:[/bold green] {html_report_path}")
        except Exception as e:
            display_error_panel(
                title="HTML Report Export Error",
                message=f"Could not save HTML report to '{html_report_path}'.",
                details=str(e)
            )

    if sarif_report_path and result:
        try:
            SARIFExporter.save_sarif_file(result, sarif_report_path, file_uri=target)
            if not raw_json:
                console.print(f"[bold green]OASIS SARIF v2.1.0 report exported to:[/bold green] {sarif_report_path}")
        except Exception as e:
            display_error_panel(
                title="SARIF Export Error",
                message=f"Could not save SARIF report to '{sarif_report_path}'.",
                details=str(e)
            )

    if patch_output_path and result:
        try:
            findings = result.get("security_findings", [])
            RemediationEngine.save_patch_file(target, findings, patch_output_path)
            if not raw_json:
                console.print(f"[bold green]Unified remediation diff patch exported to:[/bold green] {patch_output_path}")
        except Exception as e:
            display_error_panel(
                title="Remediation Patch Export Error",
                message=f"Could not save patch file to '{patch_output_path}'.",
                details=str(e)
            )

    if fail_on_risk is not None and result:
        score = int(result.get("risk_score", 1))
        if score >= fail_on_risk:
            if not raw_json:
                console.print(f"\n[bold red]CI/CD Quality Gate Failed:[/bold red] Risk score {score}/10 exceeds fail threshold {fail_on_risk}/10.")
            sys.exit(1)


async def run_audit_directory(
    directory: str,
    sarif_report_path: str = None,
    fail_on_risk: int = None,
    chain: str = "ethereum",
    api_key: str = None,
    strict: bool = False
):
    dir_path = Path(directory)
    if not dir_path.exists():
        display_error_panel(
            title="Directory Not Found",
            message=f"The specified directory '{directory}' does not exist.",
            suggestions=["Check the directory path for typos. Example: data/test_contracts"]
        )
        return

    if not dir_path.is_dir():
        display_error_panel(
            title="Not A Directory",
            message=f"'{directory}' is a file, not a directory.",
            suggestions=["Use 'audit-contract' to audit a single file."]
        )
        return

    sol_files = list(dir_path.glob("**/*.sol"))
    if not sol_files:
        display_error_panel(
            title="No Solidity Files Found",
            message=f"No '.sol' files were found inside '{directory}'.",
            suggestions=["Ensure Solidity contract files end with the '.sol' extension."]
        )
        return

    console.print(f"[bold cyan]Auditing {len(sol_files)} Solidity contract(s) in {directory}...[/bold cyan]\n")
    pipeline = ChainMindPipeline(etherscan_api_key=api_key, chain=chain, strict_mode=strict)
    summary_data = []
    combined_findings = []

    for sol_file in sol_files:
        try:
            with open(sol_file, "r", encoding="utf-8") as f:
                code = f.read()
            if not code.strip():
                console.print(f"[yellow]⚠️ Skipping empty contract file: {sol_file.name}[/yellow]")
                continue

            res = await pipeline.audit_smart_contract_source(
                raw_source=code,
                target_address=f"File::{sol_file.name}",
                raw_json_output=False
            )
            summary_data.append({
                "file": sol_file.name,
                "risk_score": res.get("risk_score", 1),
                "findings_count": len(res.get("security_findings", [])),
                "injections": res.get("ingestion_telemetry", {}).get("detected_injections", 0)
            })
            for item in res.get("security_findings", []):
                item_copy = dict(item)
                item_copy["location"] = f"{sol_file.name}:{item_copy.get('location', '')}"
                combined_findings.append(item_copy)
        except Exception as file_err:
            console.print(f"[bold red]❌ Error auditing {sol_file.name}: {file_err}[/bold red]")

    if not summary_data:
        display_error_panel(
            title="Batch Audit Incomplete",
            message="No valid contracts could be successfully processed in this directory."
        )
        return

    # Summary table
    table = Table(title="Batch Audit Summary", safe_box=True)
    table.add_column("Contract File", style="bold white")
    table.add_column("Risk Score", style="bold")
    table.add_column("Security Flags", justify="center")
    table.add_column("Injections Defended", justify="center")

    for item in summary_data:
        score = item["risk_score"]
        score_color = "green" if score <= 3 else ("yellow" if score <= 6 else "red")
        table.add_row(
            item["file"],
            f"[{score_color}]{score}/10[/{score_color}]",
            str(item["findings_count"]),
            f"[green]{item['injections']}[/green]" if item["injections"] == 0 else f"[red]{item['injections']}[/red]"
        )

    console.print()
    console.print(table)

    if sarif_report_path:
        try:
            dummy_report = {
                "target_address": directory,
                "security_findings": combined_findings
            }
            SARIFExporter.save_sarif_file(dummy_report, sarif_report_path, file_uri=directory)
            console.print(f"[bold green]Aggregated SARIF report exported to:[/bold green] {sarif_report_path}")
        except Exception as e:
            display_error_panel(title="SARIF Export Error", message=f"Could not save SARIF file: {e}")

    if fail_on_risk is not None:
        max_score = max((item["risk_score"] for item in summary_data), default=1)
        if max_score >= fail_on_risk:
            console.print(f"\n[bold red]CI/CD Quality Gate Failed:[/bold red] Maximum risk score {max_score}/10 exceeds fail threshold {fail_on_risk}/10.")
            sys.exit(1)


async def run_mempool(live: bool, count: int, interval: float, window: float, threshold: int, chain: str = "ethereum"):
    try:
        console.print(f"[bold cyan]Starting Chain-Mind Mempool Stream Engine...[/bold cyan]")
        console.print(f"[dim]Network: {chain.upper()} | Mode: {'Live WebSocket RPC' if live else 'High-Fidelity Simulation'} | Sliding Window: {window}s | Threshold: {threshold} txs[/dim]")
        if live:
            console.print("[dim white]Streaming live pending transactions from Ethereum node. Press Ctrl+C at any time to stop.[/dim white]\n")
        else:
            console.print("[dim white]Running synthetic attack simulation. Press Ctrl+C at any time to stop.[/dim white]\n")

        pipeline = ChainMindPipeline(chain=chain, sliding_window_sec=window, anomaly_threshold=threshold)
        await pipeline.stream_mempool(simulate=not live, count=count, interval=interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚡ Mempool stream stopped by user (Ctrl+C).[/bold yellow]\n")
    except ConnectionError as conn_err:
        display_error_panel(
            title="Ethereum RPC Connection Error",
            message=str(conn_err),
            suggestions=[
                "Check your internet connection.",
                "Verify your WebSocket RPC URL.",
                "Try setting a custom Alchemy/Infura endpoint: $env:ETH_RPC_WS_URL=\"wss://...\"",
                "To test without an internet connection, use simulation mode (Option 5 in the menu)."
            ]
        )
    except Exception as exc:
        display_error_panel(
            title="Mempool Stream Error",
            message="An unexpected error halted the mempool stream.",
            details=str(exc),
            suggestions=[
                "Ensure your network allows WebSocket traffic.",
                "Check that the target network name is valid."
            ]
        )


def view_history(limit: int, anomalies: bool):
    try:
        db = AuditDatabase()
        if anomalies:
            records = db.get_recent_anomalies(limit=limit)
            if not records:
                console.print(Panel(
                    "[dim white]No mempool anomalies recorded in the database yet.\n"
                    "High-frequency bursts and malicious calls will be logged here automatically when detected.[/dim white]",
                    title="[bold yellow]Mempool Anomaly Log (Empty)[/bold yellow]",
                    border_style="yellow",
                    safe_box=True
                ))
                return
            table = Table(title="Persisted Mempool Anomaly Log", safe_box=True)
            table.add_column("ID", width=4)
            table.add_column("Tx Hash", width=18)
            table.add_column("Sender", width=14)
            table.add_column("Selector", width=10)
            table.add_column("Classification", width=22)
            table.add_column("Burst Count", justify="center")
            table.add_column("Detected At", width=20)

            for r in records:
                table.add_row(
                    str(r["id"]),
                    str(r["tx_hash"])[:16] + "...",
                    str(r["sender"])[:12] + "...",
                    str(r["function_selector"] or "0x"),
                    r["classification"],
                    str(r["frequency_count"]),
                    str(r["detected_at"])
                )
            console.print(table)
        else:
            records = db.get_recent_audits(limit=limit)
            if not records:
                console.print(Panel(
                    "[dim white]No contract audits recorded in the database yet.\n"
                    "Run an audit on any contract to populate this history.[/dim white]",
                    title="[bold yellow]Contract Audit History (Empty)[/bold yellow]",
                    border_style="yellow",
                    safe_box=True
                ))
                return
            table = Table(title="Persisted Smart Contract Audit History", safe_box=True)
            table.add_column("ID", width=4)
            table.add_column("Target Address / File", width=30)
            table.add_column("Risk Score", justify="center")
            table.add_column("Injections Neutralized", justify="center")
            table.add_column("Audit Timestamp", width=25)

            for r in records:
                score = r["risk_score"]
                score_color = "green" if score <= 3 else ("yellow" if score <= 6 else "red")
                table.add_row(
                    str(r["id"]),
                    r["target_address"],
                    f"[{score_color}]{score}/10[/{score_color}]",
                    str(r["detected_injections"]),
                    r["audit_timestamp"][:19]
                )
            console.print(table)
    except Exception as exc:
        display_error_panel(
            title="Database Query Error",
            message="Could not read audit records from database.",
            details=str(exc),
            suggestions=[
                "Ensure 'audit_history.db' is not locked by another process.",
                "Verify file permissions in the workspace directory."
            ]
        )


def interactive_menu():
    """Interactive menu for end users: zero commands or flags needed to operate and configure."""
    from rich.prompt import Prompt, Confirm

    # Session configuration state
    state = {
        "strict_mode": False,
        "chain": "ethereum",
        "gemini_api_key": settings.gemini_api_key,
        "etherscan_api_key": settings.etherscan_api_key,
        "custom_ws_rpc": None
    }

    while True:
        console.clear()

        # Visual status indicators
        mode_text = "[bold red]STRICT REAL MODE (No Fallbacks)[/bold red]" if state["strict_mode"] else "[bold green]RESILIENT MODE (Auto-Fallback Enabled)[/bold green]"
        gemini_text = "[green]Configured[/green]" if state["gemini_api_key"] else "[yellow]Not Configured (Uses Heuristics in Resilient Mode)[/yellow]"
        etherscan_text = "[green]Configured[/green]" if state["etherscan_api_key"] else "[dim white]Default Free Tier[/dim white]"
        network_name = settings.chains.get(state["chain"], {}).get("name", state["chain"].upper())

        console.print(Panel(
            f"[bold cyan]CHAIN-MIND AUDITOR[/bold cyan] — [bold white]Blockchain Security & Ingestion Engine[/bold white]\n"
            f"[dim]Algorithmic Sanitization • DSA Sliding Window • Threat Engine • LLM / Heuristics[/dim]\n\n"
            f" [bold]Active Status:[/bold]\n"
            f"  • Operating Mode:  {mode_text}\n"
            f"  • Target Network:  [bold cyan]{network_name}[/bold cyan]\n"
            f"  • Gemini AI Key:   {gemini_text}\n"
            f"  • Explorer Key:    {etherscan_text}",
            title="[bold yellow]System Control Center[/bold yellow]",
            subtitle="[dim]Select an action (0-8)[/dim]",
            expand=False,
            safe_box=True
        ))

        console.print(r"  [bold green]\[1][/bold green] Audit a Smart Contract (Local File or 0x Ethereum Address)")
        console.print(r"  [bold green]\[2][/bold green] Stream Live Real Ethereum Mempool (Capture Real Transactions)")
        console.print(r"  [bold green]\[3][/bold green] Stream Simulated Mempool (Attack Scenarios & MEV Burst Demo)")
        console.print(r"  [bold green]\[4][/bold green] Batch Audit Test Contracts Directory (data/test_contracts)")
        console.print(r"  [bold green]\[5][/bold green] View Persisted Audit Trail & Anomaly Log (SQLite Database)")
        console.print(r"  [bold green]\[6][/bold green] Run Automated Test Suite (pytest)")
        console.print(r"  [bold cyan]\[7][/bold cyan] Toggle Operating Mode (Switch Strict Real Mode vs Resilient Mode)")
        console.print(r"  [bold cyan]\[8][/bold cyan] Settings & Keys (Configure API Keys, RPC, or Network)")
        console.print(r"  [bold green]\[9][/bold green] Launch Web Operations Center (Interactive Browser Frontend)")
        console.print(r"  [bold red]\[0][/bold red] Exit\n")

        try:
            choice = Prompt.ask("[bold yellow]Select option[/bold yellow]", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"], default="1")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold cyan]Exiting Chain-Mind Auditor.[/bold cyan]\n")
            break

        if choice == "0":
            console.print("\n[bold cyan]Exiting Chain-Mind Auditor. Goodbye![/bold cyan]\n")
            break

        try:
            # Action 1: Audit Smart Contract
            if choice == "1":
                console.print("\n[bold cyan]--- Audit Smart Contract ---[/bold cyan]")
                console.print("[dim]Select a target from the list below:[/dim]")
                console.print("  [1] VulnerableVault.sol (Test contract: Reentrancy, tx.origin, assembly)")
                console.print("  [2] SafeERC20.sol (Test contract: Secure standard token)")
                console.print("  [3] Tether USD (Real Mainnet Contract: 0xdAC17F958D2ee523a2206206994597C13D831ec7)")
                console.print("  [4] Uniswap V2 Router (Real Mainnet Contract: 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D)")
                console.print("  [5] Wrapped Ether WETH9 (Real Mainnet Contract: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)")
                console.print("  [6] Enter Custom File Path or 0x Address")

                sub = Prompt.ask("Choose target", choices=["1", "2", "3", "4", "5", "6"], default="1")
                targets = {
                    "1": "data/test_contracts/VulnerableVault.sol",
                    "2": "data/test_contracts/SafeERC20.sol",
                    "3": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                    "4": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
                    "5": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
                }

                if sub in targets:
                    target = targets[sub]
                else:
                    target = Prompt.ask("Enter .sol file path or 0x address", default="data/test_contracts/VulnerableVault.sol")

                gen_html = Confirm.ask("Generate interactive HTML report?", default=True)
                html_path = "audit_report.html" if gen_html else None

                # Create pipeline with session state
                pipeline = ChainMindPipeline(
                    etherscan_api_key=state["etherscan_api_key"],
                    gemini_api_key=state["gemini_api_key"],
                    chain=state["chain"],
                    strict_mode=state["strict_mode"]
                )

                asyncio.run(run_audit(
                    target=target,
                    raw_json=False,
                    html_report_path=html_path,
                    chain=state["chain"],
                    api_key=state["etherscan_api_key"],
                    strict=state["strict_mode"]
                ))

            # Action 2: Stream Live Real Mempool
            elif choice == "2":
                console.print(f"\n[bold cyan]--- Stream Live Real {network_name} Mempool ---[/bold cyan]")
                count_str = Prompt.ask("Transactions to capture (0 for continuous stream until Ctrl+C)", default="10")
                count = int(count_str) if count_str.isdigit() else 10

                asyncio.run(run_mempool(
                    live=True,
                    count=count,
                    interval=0.1,
                    window=10.0,
                    threshold=5,
                    chain=state["chain"]
                ))

            # Action 3: Stream Simulated Mempool
            elif choice == "3":
                console.print("\n[bold cyan]--- Stream Simulated Mempool (Attack Demos & MEV Bursts) ---[/bold cyan]")
                count_str = Prompt.ask("Transactions to simulate", default="20")
                count = int(count_str) if count_str.isdigit() else 20

                asyncio.run(run_mempool(
                    live=False,
                    count=count,
                    interval=0.15,
                    window=10.0,
                    threshold=5,
                    chain=state["chain"]
                ))

            # Action 4: Batch Audit Directory
            elif choice == "4":
                console.print("\n[bold cyan]--- Batch Audit Directory ---[/bold cyan]")
                dir_path = Prompt.ask("Directory path", default="data/test_contracts")
                asyncio.run(run_audit_directory(
                    directory=dir_path,
                    chain=state["chain"],
                    api_key=state["etherscan_api_key"],
                    strict=state["strict_mode"]
                ))

            # Action 5: View SQLite History
            elif choice == "5":
                console.print("\n[bold cyan]--- View SQLite Audit History ---[/bold cyan]")
                console.print("  [1] Smart Contract Audit Records")
                console.print("  [2] Mempool Anomaly & Attack Alerts")
                sub = Prompt.ask("Choose category", choices=["1", "2"], default="1")
                limit_str = Prompt.ask("Records to display", default="10")
                limit = int(limit_str) if limit_str.isdigit() else 10
                if sub == "1":
                    view_history(limit=limit, anomalies=False)
                else:
                    view_history(limit=limit, anomalies=True)

            # Action 6: Run Tests
            elif choice == "6":
                console.print("\n[bold cyan]--- Running Automated Test Suite (pytest) ---[/bold cyan]\n")
                import pytest
                pytest.main(["-v", "tests"])

            # Action 7: Toggle Strict Mode
            elif choice == "7":
                state["strict_mode"] = not state["strict_mode"]
                if state["strict_mode"]:
                    console.print("\n[bold red][!] STRICT REAL MODE ACTIVATED[/bold red]")
                    console.print("[dim white]Heuristic fallbacks and self-healing schema repairs are now DISABLED.\n"
                                  "Any real failure (LLM quota, bad API key, RPC disconnect) will surface immediately for debugging.[/dim white]")
                else:
                    console.print("\n[bold green][*] RESILIENT MODE ACTIVATED[/bold green]")
                    console.print("[dim white]Auto-fallback to offline heuristic security engine is now enabled if API keys are missing.[/dim white]")

            # Action 8: Settings & Keys
            elif choice == "8":
                console.print("\n[bold cyan]--- Settings & API Keys ---[/bold cyan]")
                console.print("  [1] Set Gemini API Key (Required for real AI LLM audits in Strict Mode)")
                console.print("  [2] Set Etherscan API Key (For higher explorer rate limits)")
                console.print("  [3] Select Target Blockchain Network (Ethereum, Arbitrum, Polygon, Base, Optimism)")
                console.print("  [4] Reset All Keys to Defaults")
                console.print("  [0] Back to Main Menu")

                cfg_sub = Prompt.ask("Select setting", choices=["0", "1", "2", "3", "4"], default="1")

                if cfg_sub == "1":
                    new_key = Prompt.ask("Paste your Gemini API Key (starts with AIza...)", password=True)
                    if new_key.strip():
                        state["gemini_api_key"] = new_key.strip()
                        os.environ["GEMINI_API_KEY"] = new_key.strip()
                        console.print("[bold green]Gemini API Key saved for this session![/bold green]")
                elif cfg_sub == "2":
                    new_key = Prompt.ask("Paste your Etherscan API Key")
                    if new_key.strip():
                        state["etherscan_api_key"] = new_key.strip()
                        os.environ["ETHERSCAN_API_KEY"] = new_key.strip()
                        console.print("[bold green]Etherscan API Key saved for this session![/bold green]")
                elif cfg_sub == "3":
                    console.print("Available Networks: ethereum, arbitrum, optimism, polygon, base")
                    new_chain = Prompt.ask("Target network", choices=["ethereum", "arbitrum", "optimism", "polygon", "base"], default="ethereum")
                    state["chain"] = new_chain
                    console.print(f"[bold green]Target network switched to {new_chain.upper()}![/bold green]")
                elif cfg_sub == "4":
                    state["gemini_api_key"] = settings.gemini_api_key
                    state["etherscan_api_key"] = settings.etherscan_api_key
                    state["chain"] = "ethereum"
                    state["strict_mode"] = False
                    console.print("[yellow]Settings reset to initial configuration.[/yellow]")

            # Action 9: Launch Web Operations Center
            elif choice == "9":
                run_web_server()

        except Exception as action_err:
            display_error_panel(
                title="Operation Encountered Error",
                message="An error occurred during menu action execution.",
                details=str(action_err),
                suggestions=["Check input parameters and try again."]
            )

        console.print()
        try:
            Prompt.ask("[dim]Press Enter to return to main menu...[/dim]", default="")
        except (KeyboardInterrupt, EOFError):
            break


def run_web_server(host: str = "127.0.0.1", port: int = 8000):
    """Launches the modern FastAPI web frontend and API server."""
    import uvicorn
    console.print(Panel(
        f"[bold cyan]CHAIN-MIND AUDITOR — WEB OPERATIONS CENTER[/bold cyan]\n\n"
        f" [bold green]• Web Dashboard:[/bold green]  http://{host}:{port}\n"
        f" [bold green]• Interactive API Docs:[/bold green] http://{host}:{port}/docs\n"
        f" [bold yellow]• Press Ctrl+C to halt server[/bold yellow]",
        title="[bold yellow]Server Online[/bold yellow]",
        border_style="cyan",
        safe_box=True
    ))
    uvicorn.run("src.web.server:app", host=host, port=port, reload=False)


def main():
    args = parse_args()

    if not args.command or args.command == "menu":
        interactive_menu()
        return

    if args.command == "web":
        run_web_server(host=args.host, port=args.port)
    elif args.command == "audit-contract":
        asyncio.run(run_audit(
            target=args.target,
            raw_json=args.json,
            output_file=args.output,
            html_report_path=args.html_report,
            sarif_report_path=args.sarif,
            patch_output_path=args.patch_output,
            fail_on_risk=args.fail_on_risk,
            chain=args.chain,
            api_key=args.api_key,
            strict=args.strict
        ))
    elif args.command == "audit-directory":
        asyncio.run(run_audit_directory(
            directory=args.directory,
            sarif_report_path=args.sarif,
            fail_on_risk=args.fail_on_risk,
            chain=args.chain,
            api_key=args.api_key,
            strict=args.strict
        ))
    elif args.command == "stream-mempool":
        asyncio.run(run_mempool(
            live=args.live,
            count=args.count,
            interval=args.interval,
            window=args.window,
            threshold=args.threshold,
            chain=args.chain
        ))
    elif args.command == "view-history":
        view_history(args.limit, args.anomalies)
    elif args.command == "run-tests":
        import pytest
        pytest.main(["-v", "tests"])


if __name__ == "__main__":
    main()


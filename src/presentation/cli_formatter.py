"""
Layer 3: Output Formatting and CLI Presentation Engine.

Adheres to Layer 3 Master Prompt:
1. Header Section: [CHAIN-MIND AUDIT REPORT] Banner with Address, Timestamp, Analysis Type
2. Risk Indicator:
   - SAFE (1-3): Green flag / Low Risk
   - WARNING (4-6): Yellow flag / Medium Risk
   - CRITICAL (7-10): Red flag / High Risk
3. Functional Summary & Anomaly Status
4. Breakdown of Findings & Actionable Recommendations
"""
import sys
from typing import Dict, Any, List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Initialize console with utf-8 fallback handling
console = Console(safe_box=True)


class CLIFormatter:
    @staticmethod
    def get_risk_badge(score: int) -> Tuple[str, str]:
        """Returns badge text and style based on risk score."""
        if score <= 3:
            return f"[SAFE] (Score: {score}/10 - Low Risk)", "bold green"
        elif score <= 6:
            return f"[WARNING] (Score: {score}/10 - Medium Risk)", "bold yellow"
        else:
            return f"[CRITICAL] (Score: {score}/10 - High Risk)", "bold red"

    @classmethod
    def display_contract_audit_report(cls, report: Dict[str, Any]):
        """Renders full contract security audit report to terminal."""
        target_addr = report.get("target_address", "Unknown")
        timestamp = report.get("audit_timestamp", "N/A")
        analysis_type = report.get("analysis_type", "SMART_CONTRACT_AUDIT")
        score = report.get("risk_score", 1)
        summary = report.get("summary", "No summary available.")
        findings: List[Dict[str, Any]] = report.get("security_findings", [])
        anomaly = report.get("anomaly_flag", {})
        recommendations: List[str] = report.get("actionable_recommendations", [])
        telemetry = report.get("ingestion_telemetry", {})

        badge_text, badge_style = cls.get_risk_badge(score)

        console.print()
        console.rule("[bold cyan]CHAIN-MIND AUDIT REPORT[/bold cyan]")

        # Header Info Table
        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="bold white")
        info_table.add_column(style="cyan")
        info_table.add_row("Target Address :", str(target_addr))
        info_table.add_row("Audit Timestamp:", str(timestamp))
        info_table.add_row("Analysis Type  :", str(analysis_type))
        info_table.add_row("Security Status:", f"[{badge_style}]{badge_text}[/{badge_style}]")

        if telemetry:
            injections = telemetry.get("detected_injections", 0)
            inj_style = "bold red" if injections > 0 else "bold green"
            info_table.add_row(
                "Ingestion Guard:",
                f"[{inj_style}]{injections} Prompt Injection Attempt(s) Neutralized[/{inj_style}]"
            )

        console.print(Panel(info_table, title="[bold white]Overview[/bold white]", border_style="cyan"))

        # Functional Summary
        console.print(Panel(f"[italic]{summary}[/italic]", title="[bold white]Functional Summary[/bold white]", border_style="blue"))

        # Findings Breakdown
        if findings:
            findings_table = Table(
                title="Security Findings & Vulnerability Breakdown",
                border_style="red" if score >= 7 else "yellow",
                safe_box=True
            )
            findings_table.add_column("Severity", style="bold", width=12)
            findings_table.add_column("Category", style="cyan", width=25)
            findings_table.add_column("Location", style="dim", width=25)
            findings_table.add_column("Description", style="white")

            for f in findings:
                sev = f.get("severity", "LOW")
                sev_color = {
                    "CRITICAL": "bold red",
                    "HIGH": "bold red",
                    "MEDIUM": "bold yellow",
                    "LOW": "bold green",
                    "INFO": "bold blue"
                }.get(sev, "white")

                findings_table.add_row(
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    f.get("category", "N/A"),
                    f.get("location", "N/A"),
                    f.get("description", "N/A")
                )
            console.print(findings_table)
        else:
            console.print(Panel("[bold green][SAFE] No critical vulnerabilities or dangerous anti-patterns detected.[/bold green]", border_style="green"))

        # Actionable Recommendations
        if recommendations:
            rec_text = "\n".join([f"  * {rec}" for rec in recommendations])
            console.print(Panel(rec_text, title="[bold white]Actionable Recommendations[/bold white]", border_style="green"))

        console.print()

    @classmethod
    def display_mempool_tx_alert(cls, tx_data: Dict[str, Any], anomaly_data: Dict[str, Any]):
        """Renders live mempool transaction log entry."""
        is_anomalous = anomaly_data.get("is_anomalous", False)
        tx_hash = str(tx_data.get("tx_hash", "0x0"))[:16] + "..."
        sender = str(tx_data.get("sender", "0x0"))
        target = str(tx_data.get("target", "0x0"))
        classification = tx_data.get("payload_classification", "STANDARD_CALL")
        selector = tx_data.get("function_selector") or "0x"
        rate = anomaly_data.get("count_in_window", 1)
        window = anomaly_data.get("window_seconds", 10)

        if is_anomalous:
            tag = "[bold red][ANOMALY ALERT][/bold red]"
        elif classification == "SUSPICIOUS_HIGH_RISK_CALL":
            tag = "[bold red][CRITICAL CALL][/bold red]"
        elif classification == "CONTRACT_CREATION":
            tag = "[bold magenta][DEPLOYMENT][/bold magenta]"
        elif classification == "ETH_TRANSFER":
            tag = "[bold blue][ETH TRANSFER][/bold blue]"
        else:
            tag = "[bold green][MEMPOOL TX][/bold green]"

        desc = f"{tag} {tx_hash} | From: {sender[:10]}... | To: {target[:10]}... | Type: {classification} ({selector})"
        if is_anomalous:
            desc += f" | [bold red]High Frequency: {rate} txs in {window}s![/bold red]"

        console.print(desc)

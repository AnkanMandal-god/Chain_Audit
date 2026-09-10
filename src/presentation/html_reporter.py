"""
Layer 3: Standalone Interactive HTML Audit Report Generator.

Produces self-contained, beautifully styled HTML reports suitable for
clients, developers, and compliance audits with visual risk gauges,
findings breakdowns, and actionable remediation diffs.
"""
import html
from pathlib import Path
from typing import Dict, Any, List
from src.presentation.remediation_engine import RemediationEngine


class HTMLReporter:
    @classmethod
    def generate_report_html(cls, report: Dict[str, Any]) -> str:
        """Renders complete HTML audit report string."""
        target_addr = html.escape(str(report.get("target_address", "Unknown")))
        timestamp = html.escape(str(report.get("audit_timestamp", "N/A")))
        score = int(report.get("risk_score", 1))
        summary = html.escape(str(report.get("summary", "No summary provided.")))
        findings: List[Dict[str, Any]] = report.get("security_findings", [])
        telemetry = report.get("ingestion_telemetry", {})
        injections = int(telemetry.get("detected_injections", 0))

        # Risk badge color & styling
        if score <= 3:
            badge_class = "badge-safe"
            badge_text = f"SAFE ({score}/10)"
            accent_color = "#10b981"
        elif score <= 6:
            badge_class = "badge-warning"
            badge_text = f"WARNING ({score}/10)"
            accent_color = "#f59e0b"
        else:
            badge_class = "badge-critical"
            badge_text = f"CRITICAL ({score}/10)"
            accent_color = "#ef4444"

        # Generate findings HTML
        findings_html = ""
        remediations = RemediationEngine.get_remediations_for_findings(findings)
        rem_map = {r["category"]: r for r in remediations}

        if findings:
            for f in findings:
                sev = html.escape(f.get("severity", "LOW"))
                cat = html.escape(f.get("category", "Vulnerability"))
                loc = html.escape(f.get("location", "N/A"))
                desc = html.escape(f.get("description", ""))
                sev_class = f"sev-{sev.lower()}"

                # Check if remediation patch available
                rem_patch = rem_map.get(f.get("category"))
                diff_block = ""
                if rem_patch:
                    clean_diff = html.escape(rem_patch["diff"].replace("```diff\n", "").replace("\n```", ""))
                    diff_block = f"""
                    <details class="remediation-details">
                        <summary>View Recommended Code Fix ({html.escape(rem_patch['title'])})</summary>
                        <pre class="diff-block"><code>{clean_diff}</code></pre>
                    </details>
                    """

                findings_html += f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="sev-tag {sev_class}">{sev}</span>
                        <h3 class="finding-title">{cat}</h3>
                    </div>
                    <div class="finding-loc"><strong>Location:</strong> <code>{loc}</code></div>
                    <p class="finding-desc">{desc}</p>
                    {diff_block}
                </div>
                """
        else:
            findings_html = """
            <div class="clean-box">
                <div class="clean-icon">&#10004;</div>
                <h3>No Critical Vulnerabilities Detected</h3>
                <p>The contract adheres to standard Solidity security practices.</p>
            </div>
            """

        recommendations_html = ""
        for rec in report.get("actionable_recommendations", []):
            recommendations_html += f"<li>{html.escape(rec)}</li>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chain-Mind Audit Report: {target_addr}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-border: #1f2937;
            --text-main: #f9fafb;
            --text-dim: #9ca3af;
            --accent: {accent_color};
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text-main);
            font-family: var(--font);
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--surface-border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .brand {{
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: #38bdf8;
        }}
        .brand span {{ color: #f9fafb; }}
        .badge {{
            padding: 8px 18px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.95rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-safe {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}

        .overview-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 20px;
        }}
        .metric-label {{ font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 6px; }}
        .metric-val {{ font-size: 1.1rem; font-weight: 700; word-break: break-all; }}
        
        .section-box {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 32px;
        }}
        h2 {{ font-size: 1.3rem; margin-bottom: 16px; color: #38bdf8; }}
        
        .finding-card {{
            background: #1e293b;
            border-left: 4px solid var(--accent);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
        .finding-title {{ font-size: 1.1rem; font-weight: 700; }}
        .sev-tag {{
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 800;
        }}
        .sev-critical {{ background: #dc2626; color: #fff; }}
        .sev-high {{ background: #ea580c; color: #fff; }}
        .sev-medium {{ background: #d97706; color: #fff; }}
        .sev-low {{ background: #059669; color: #fff; }}
        .finding-loc {{ font-size: 0.85rem; color: var(--text-dim); margin-bottom: 10px; }}
        .finding-loc code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
        .finding-desc {{ font-size: 0.95rem; color: #e2e8f0; margin-bottom: 14px; }}

        .remediation-details {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 12px 16px;
            margin-top: 12px;
        }}
        .remediation-details summary {{
            cursor: pointer;
            font-weight: 600;
            color: #38bdf8;
        }}
        .diff-block {{
            margin-top: 12px;
            background: #020617;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.85rem;
            color: #94a3b8;
        }}
        
        .clean-box {{ text-align: center; padding: 40px; }}
        .clean-icon {{ font-size: 3rem; color: #10b981; margin-bottom: 12px; }}
        ul.recs-list {{ padding-left: 20px; }}
        ul.recs-list li {{ margin-bottom: 8px; color: #cbd5e1; }}
        footer {{ text-align: center; color: var(--text-dim); font-size: 0.8rem; margin-top: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">CHAIN-MIND <span>AUDITOR</span></div>
            <div class="badge {badge_class}">{badge_text}</div>
        </header>

        <div class="overview-grid">
            <div class="metric-card">
                <div class="metric-label">Target Address / File</div>
                <div class="metric-val">{target_addr}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Audit Timestamp</div>
                <div class="metric-val">{timestamp}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Defensive Firewall</div>
                <div class="metric-val" style="color: {'#10b981' if injections == 0 else '#ef4444'}">{injections} Injections Neutralized</div>
            </div>
        </div>

        <div class="section-box">
            <h2>Functional Summary</h2>
            <p style="font-style: italic; color: #cbd5e1;">{summary}</p>
        </div>

        <div class="section-box">
            <h2>Vulnerability & Security Findings</h2>
            {findings_html}
        </div>

        <div class="section-box">
            <h2>Actionable Recommendations</h2>
            <ul class="recs-list">
                {recommendations_html}
            </ul>
        </div>

        <footer>
            Generated by Chain-Mind Auditor &bull; Smart Contract Ingestion & Security Analysis Engine
        </footer>
    </div>
</body>
</html>"""

    @classmethod
    def save_html_report(cls, report: Dict[str, Any], output_path: str):
        """Generates and writes HTML report to specified file path."""
        html_content = cls.generate_report_html(report)
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html_content)

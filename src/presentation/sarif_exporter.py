"""
Layer 3: SARIF (Static Analysis Results Interchange Format v2.1.0) Exporter.

Converts Chain-Mind Auditor reports into standard OASIS SARIF format
for direct integration with GitHub Security Code Scanning (upload-sarif action)
and enterprise SIEM / DevSecOps pipelines.
"""
import json
from pathlib import Path
from typing import Dict, Any, List


class SARIFExporter:
    SEVERITY_LEVEL_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note"
    }

    @classmethod
    def generate_sarif(cls, report: Dict[str, Any], file_uri: str = None) -> Dict[str, Any]:
        """Generates OASIS SARIF v2.1.0 schema dictionary from audit report."""
        target = file_uri or report.get("target_address", "contract.sol")
        # Clean target name for URI
        if target.startswith("File::") or target.startswith("LocalFile::"):
            target = target.split("::", 1)[1]

        findings: List[Dict[str, Any]] = report.get("security_findings", [])
        rules_dict = {}
        results_list = []

        for idx, f in enumerate(findings):
            category = f.get("category", "General Vulnerability")
            rule_id = "CMA-" + "".join(word[:4].upper() for word in category.split())[:12]
            severity = f.get("severity", "MEDIUM").upper()
            sarif_level = cls.SEVERITY_LEVEL_MAP.get(severity, "warning")
            desc = f.get("description", "Vulnerability detected by Chain-Mind Auditor.")
            loc_str = str(f.get("location", ""))

            # Register rule metadata
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": category,
                    "shortDescription": {"text": category},
                    "fullDescription": {"text": desc},
                    "defaultConfiguration": {"level": sarif_level},
                    "help": {
                        "text": f"Remediation guidance: Review {category} and follow best security practices."
                    }
                }

            # Estimate startLine if location has line number
            start_line = 1
            if "line" in loc_str.lower():
                import re
                line_match = re.search(r'line\s*(\d+)', loc_str, re.IGNORECASE)
                if line_match:
                    start_line = int(line_match.group(1))

            results_list.append({
                "ruleId": rule_id,
                "ruleIndex": list(rules_dict.keys()).index(rule_id),
                "level": sarif_level,
                "message": {"text": f"[{severity}] {desc}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": start_line
                            }
                        }
                    }
                ]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Chain-Mind Auditor",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/chainmind/auditor",
                            "rules": list(rules_dict.values())
                        }
                    },
                    "results": results_list
                }
            ]
        }
        return sarif_doc

    @classmethod
    def save_sarif_file(cls, report: Dict[str, Any], output_path: str, file_uri: str = None):
        """Generates and writes SARIF JSON report to target path."""
        sarif_data = cls.generate_sarif(report, file_uri=file_uri)
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

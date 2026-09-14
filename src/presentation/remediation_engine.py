"""
Layer 3: Automated Remediation Code Diff Generator.

Produces concrete code patches and remediation diffs for developers
addressing detected smart contract vulnerabilities.
"""
import re
from typing import Dict, Any, List


class RemediationEngine:
    REMEDIATION_PATCHES = {
        "Reentrancy": {
            "title": "Apply Checks-Effects-Interactions & ReentrancyGuard",
            "diff": """```diff
-   function withdraw(uint256 amount) external {
-       (bool success, ) = msg.sender.call{value: amount}("");
-       require(success, "Transfer failed");
-       balances[msg.sender] -= amount;
-   }
+   // 1. Inherit OpenZeppelin's ReentrancyGuard
+   function withdraw(uint256 amount) external nonReentrant {
+       // 2. Checks
+       require(balances[msg.sender] >= amount, "Insufficient balance");
+       // 3. Effects (state modified BEFORE external call)
+       balances[msg.sender] -= amount;
+       // 4. Interactions
+       (bool success, ) = msg.sender.call{value: amount}("");
+       require(success, "Transfer failed");
+   }
```"""
        },
        "Insecure Authentication (tx.origin)": {
            "title": "Replace tx.origin with msg.sender",
            "diff": """```diff
-   require(tx.origin == owner, "Not owner");
+   // msg.sender represents the immediate caller (prevents phishing proxies)
+   require(msg.sender == owner, "Not owner");
```"""
        },
        "Unchecked Return Value": {
            "title": "Validate Low-Level Call Success Boolean",
            "diff": """```diff
-   recipient.call{value: amount}("");
+   (bool success, ) = recipient.call{value: amount}("");
+   require(success, "External call failed");
```"""
        },
        "Unprotected Initializer": {
            "title": "Add OpenZeppelin 'initializer' Modifier",
            "diff": """```diff
-   function initialize(address _owner) public {
-       owner = _owner;
-   }
+   // Use OpenZeppelin Initializable.sol to prevent frontrunning
+   function initialize(address _owner) public initializer {
+       require(_owner != address(0), "Invalid owner");
+       owner = _owner;
+   }
```"""
        },
        "Missing Zero-Address Validation": {
            "title": "Enforce Zero-Address Guard on Address Assignments",
            "diff": """```diff
-   owner = newOwner;
+   require(newOwner != address(0), "Zero address not allowed");
+   owner = newOwner;
```"""
        },
        "Timestamp Dependence": {
            "title": "Replace block.timestamp with Chainlink VRF or Commit-Reveal",
            "diff": """```diff
-   uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
+   // Use Chainlink VRF (Verifiable Random Function) for tamper-proof randomness
+   uint256 requestId = COORDINATOR.requestRandomWords(...);
```"""
        },
        "Integer Overflow/Underflow": {
            "title": "Upgrade to Solidity ^0.8.0 or Use SafeMath",
            "diff": """```diff
-   pragma solidity ^0.7.6;
-   balances[msg.sender] += amount;
+   pragma solidity ^0.8.20; // Native overflow checks enabled
+   balances[msg.sender] += amount;
```"""
        }
    }

    @classmethod
    def get_remediations_for_findings(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Matches findings with actionable remediation diffs."""
        remediations = []
        seen_categories = set()

        for f in findings:
            cat = f.get("category", "")
            if cat in cls.REMEDIATION_PATCHES and cat not in seen_categories:
                seen_categories.add(cat)
                patch = cls.REMEDIATION_PATCHES[cat]
                remediations.append({
                    "category": cat,
                    "title": patch["title"],
                    "diff": patch["diff"]
                })
        return remediations

    @classmethod
    def generate_patch_file(cls, target_filename: str, findings: List[Dict[str, Any]]) -> str:
        """
        Generates a unified diff patch string compatible with 'git apply'.
        """
        remediations = cls.get_remediations_for_findings(findings)
        if not remediations:
            return ""

        patch_lines = [
            f"# Chain-Mind Auditor Remediation Patch",
            f"# Target: {target_filename}",
            f"--- a/{target_filename}",
            f"+++ b/{target_filename}",
        ]

        for rem in remediations:
            patch_lines.append(f"\n# --- Vulnerability Fix: {rem['category']} ({rem['title']}) ---")
            raw_diff = rem["diff"].replace("```diff\n", "").replace("\n```", "").replace("```", "")
            patch_lines.append(raw_diff)

        return "\n".join(patch_lines) + "\n"

    @classmethod
    def generate_refined_contract(cls, source: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Produce a conservative offline refinement for the common findings.

        This is intentionally not presented as a substitute for compilation,
        unit tests, or a human review. It gives resilient/offline mode a useful
        secure baseline while the LLM path can produce a deeper rewrite.
        """
        if not findings:
            return {
                "status": "SAFE_NO_REWRITE",
                "contract_source": source,
                "changes": [],
                "explanation": "No vulnerability findings were returned, so the source was not rewritten."
            }

        revised = source
        changes = []
        categories = {str(item.get("category", "")) for item in findings}

        if "Insecure Authentication (tx.origin)" in categories and "tx.origin" in revised:
            revised = revised.replace("tx.origin", "msg.sender")
            changes.append("Replaced tx.origin authorization checks with msg.sender.")

        if "Unchecked Return Value" in categories:
            revised = revised.replace(
                "recipient.call{value: amount}(\"\");",
                '(bool success, ) = recipient.call{value: amount}("");\n        require(success, "External call failed");'
            )
            changes.append("Added explicit success checking to the common low-level call pattern.")

        if "Reentrancy" in categories and "nonReentrant" not in revised:
            import_line = 'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\n'
            if "ReentrancyGuard.sol" not in revised:
                revised = import_line + revised
            contract_match = re.search(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", revised)
            if contract_match:
                start, end = contract_match.span()
                declaration = revised[start:end].rstrip(" {")
                if "ReentrancyGuard" not in declaration:
                    revised = revised[:start] + declaration + " is ReentrancyGuard {\n" + revised[end:]
            for fn_name in ("withdraw", "claim", "redeem", "unstake"):
                revised = re.sub(
                    rf"(function\s+{fn_name}\s*\([^)]*\)\s*(?:external|public))(\s*)(\{{)",
                    r"\1 nonReentrant\2\3",
                    revised,
                    count=1
                )
            changes.append("Added an OpenZeppelin ReentrancyGuard baseline to common withdrawal-style entry points.")

        if "Missing Zero-Address Validation" in categories:
            revised = re.sub(
                r"(\b(?:owner|admin|recipient|newOwner)\s*=\s*([A-Za-z_][A-Za-z0-9_]*);)",
                r"require(\2 != address(0), \"Zero address not allowed\");\n        \1",
                revised,
                count=1
            )
            changes.append("Added a zero-address guard before the first matching assignment.")

        header = (
            "// Chain-Mind offline remediation baseline.\n"
            "// Compile, test, and review this generated source before deployment.\n"
        )
        if not revised.startswith("// Chain-Mind offline remediation baseline."):
            revised = header + revised

        if not changes:
            changes.append("Generated a review-ready baseline with the original source preserved; no safe automatic rewrite matched.")
        return {
            "status": "REVIEW_REQUIRED",
            "contract_source": revised,
            "changes": changes,
            "explanation": "Only contracts with findings are rewritten. The result is a conservative baseline and must be compiled and reviewed before deployment."
        }

    @classmethod
    def save_patch_file(cls, target_filename: str, findings: List[Dict[str, Any]], output_path: str):
        """Saves unified remediation patch to disk."""
        patch_content = cls.generate_patch_file(target_filename, findings)
        from pathlib import Path
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(patch_content)

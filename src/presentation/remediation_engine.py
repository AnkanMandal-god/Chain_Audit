"""
Layer 3: Automated Remediation Code Diff Generator.

Produces concrete code patches and remediation diffs for developers
addressing detected smart contract vulnerabilities.
"""
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
    def save_patch_file(cls, target_filename: str, findings: List[Dict[str, Any]], output_path: str):
        """Saves unified remediation patch to disk."""
        patch_content = cls.generate_patch_file(target_filename, findings)
        from pathlib import Path
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(patch_content)

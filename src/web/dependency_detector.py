"""
Dependency and Relationship Discovery Engine for Smart Contracts.

Analyzes Solidity source code to detect inheritance (is Base), imports,
interface implementations, and external contract calls. Enables automated
clustering and batch auditing of interconnected smart contract systems.
"""
import re
import os
from pathlib import Path
from typing import Dict, Any, List, Set, Optional


class ContractRelationshipDetector:
    # Regex patterns for relationship discovery
    IMPORT_PATTERN = re.compile(r'import\s+(?:(?:\{[^}]*\}|\*\s+as\s+[A-Za-z0-9_]+)\s+from\s+)?["\']([^"\']+)["\'];', re.MULTILINE)
    CONTRACT_DEF_PATTERN = re.compile(r'(contract|interface|abstract\s+contract|library)\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{', re.MULTILINE)
    USING_PATTERN = re.compile(r'using\s+([A-Za-z0-9_]+)\s+for\s+[^;]+;', re.MULTILINE)
    CAST_OR_CALL_PATTERN = re.compile(r'\b([A-Z][A-Za-z0-9_]*)\s*\(\s*(?:address\b|[0-9a-zA-Z_]+)\s*\)', re.MULTILINE)

    @classmethod
    def analyze_source(cls, source_code: str, file_identifier: str = "Unknown") -> Dict[str, Any]:
        """
        Parses a single source file for contracts, interfaces, inheritance, imports, and references.
        """
        imports = cls.IMPORT_PATTERN.findall(source_code)
        
        contracts = []
        for match in cls.CONTRACT_DEF_PATTERN.finditer(source_code):
            kind = match.group(1).strip()
            name = match.group(2).strip()
            inherits_raw = match.group(3)
            
            parents = []
            if inherits_raw:
                # e.g. "Ownable, ReentrancyGuard, IERC20"
                parents = [p.strip().split('(')[0].strip() for p in inherits_raw.split(',') if p.strip()]

            contracts.append({
                "name": name,
                "kind": kind,
                "parents": parents,
                "file": file_identifier
            })

        # Find used libraries (e.g., using SafeERC20 for IERC20)
        libraries_used = list(set(cls.USING_PATTERN.findall(source_code)))

        # Find external contract/interface calls e.g., IERC20(token).transfer
        calls = set(cls.CAST_OR_CALL_PATTERN.findall(source_code))
        # Filter out common Solidity types
        solidity_types = {"uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
                          "int", "int8", "int256", "bytes", "bytes4", "bytes32", "string", "address", "payable"}
        external_references = [c for c in calls if c.lower() not in solidity_types and not c.startswith("uint") and not c.startswith("bytes")]

        return {
            "file": file_identifier,
            "contracts": contracts,
            "imports": imports,
            "libraries_used": libraries_used,
            "external_references": list(external_references)
        }

    @classmethod
    def scan_directory(cls, dir_path: Path) -> Dict[str, Dict[str, Any]]:
        """
        Scans all .sol files in a directory and maps each file's analysis.
        """
        results = {}
        if not dir_path.exists() or not dir_path.is_dir():
            return results

        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".sol"):
                    fpath = Path(root) / file
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            src = f.read()
                        rel_path = str(fpath.relative_to(dir_path))
                        results[rel_path] = cls.analyze_source(src, file_identifier=rel_path)
                    except Exception:
                        continue
        return results

    @classmethod
    def build_dependency_graph(
        cls,
        files_analysis: Dict[str, Dict[str, Any]],
        target_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Constructs a complete node/edge graph from scanned files,
        and identifies the batch of related contracts.
        """
        nodes = []
        edges = []
        contract_to_file = {}
        file_to_contracts = {}

        for rel_path, analysis in files_analysis.items():
            file_to_contracts[rel_path] = []
            for c in analysis["contracts"]:
                contract_name = c["name"]
                contract_to_file[contract_name] = rel_path
                file_to_contracts[rel_path].append(contract_name)
                nodes.append({
                    "id": contract_name,
                    "name": contract_name,
                    "kind": c["kind"],
                    "file": rel_path,
                    "is_target": (rel_path == target_file or contract_name == target_file) if target_file else False
                })

        # Build edges: inheritance, imports, library, references
        for rel_path, analysis in files_analysis.items():
            # 1. Imports
            for imp in analysis["imports"]:
                # Match imported file to known files
                imp_clean = Path(imp).name
                for fpath, c_names in file_to_contracts.items():
                    if Path(fpath).name == imp_clean:
                        for c_name in c_names:
                            edges.append({
                                "source": rel_path,
                                "target": c_name,
                                "type": "imports",
                                "label": f"Imports {imp_clean}"
                            })

            # 2. Inheritance & usages
            for c in analysis["contracts"]:
                c_name = c["name"]
                for p in c["parents"]:
                    edges.append({
                        "source": c_name,
                        "target": p,
                        "type": "inherits",
                        "label": f"{c_name} is {p}"
                    })
                for lib in analysis["libraries_used"]:
                    edges.append({
                        "source": c_name,
                        "target": lib,
                        "type": "uses_library",
                        "label": f"uses {lib}"
                    })
                for ref in analysis["external_references"]:
                    if ref in contract_to_file and ref != c_name:
                        edges.append({
                            "source": c_name,
                            "target": ref,
                            "type": "references",
                            "label": f"calls/casts {ref}"
                        })

        # If a target is provided, find all connected contracts (transitive closure)
        related_contracts = set()
        related_files = set()

        if target_file:
            # Find starting contract nodes
            start_nodes = set()
            for n in nodes:
                if n["file"] == target_file or n["name"] == target_file:
                    start_nodes.add(n["id"])
                    related_files.add(n["file"])

            # Traverse edges both directions to find the complete interconnected ecosystem
            to_visit = list(start_nodes)
            visited = set(start_nodes)

            while to_visit:
                curr = to_visit.pop(0)
                related_contracts.add(curr)
                if curr in contract_to_file:
                    related_files.add(contract_to_file[curr])

                for e in edges:
                    if e["source"] == curr and e["target"] not in visited:
                        visited.add(e["target"])
                        to_visit.append(e["target"])
                    elif e["target"] == curr and e["source"] not in visited:
                        visited.add(e["source"])
                        to_visit.append(e["source"])
        else:
            related_contracts = {n["id"] for n in nodes}
            related_files = set(files_analysis.keys())

        # Flag nodes that are in the related batch
        for n in nodes:
            n["in_batch"] = n["id"] in related_contracts

        return {
            "target": target_file,
            "nodes": nodes,
            "edges": edges,
            "related_contracts": sorted(list(related_contracts)),
            "related_files": sorted(list(related_files)),
            "total_nodes": len(nodes),
            "batch_size": len(related_files)
        }

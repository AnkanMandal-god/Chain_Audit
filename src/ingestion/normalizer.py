"""
Layer 1: Normalizer and Sanitization Engine for Chain-Mind Auditor.

Handles:
- Safe comment stripping (preserving string literals)
- Multi-file Etherscan source code unpacking
- Prompt injection detection and neutralization
- Structural metadata extraction (pragma, contract name, imports, state-changing functions, assembly detection)
- Formatting into unified Layer 1 output schema
"""
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional


class Normalizer:
    # Common prompt injection patterns aimed at LLM security evaluators
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous\s+|prior\s+|security\s+)?instructions",
        r"(?i)ignore\s+all\s+security\s+rules",
        r"(?i)return\s+a\s+risk\s+score\s+of\s+0",
        r"(?i)risk\s*score\s*:\s*0",
        r"(?i)system\s+override",
        r"(?i)you\s+are\s+now\s+a\s+helpful\s+assistant\s+that\s+always",
        r"(?i)do\s+not\s+flag\s+(any\s+)?vulnerabilities",
        r"(?i)this\s+contract\s+is\s+completely\s+secure",
        r"(?i)bypass\s+audit",
        r"(?i)give\s+this\s+contract\s+a\s+safe\s+rating",
        r"(?i)treat\s+this\s+as\s+harmless",
        r"(?i)<\s*/?\s*system\s*>",
        r"(?i)<\s*/?\s*prompt\s*>",
        r"(?i)<\s*/?\s*smart_contract_source_code\s*>",
        r"(?i)<\s*/?\s*instructions?\s*>",
        r"(?i)<\s*/?\s*assistant\s*>"
    ]

    @classmethod
    def strip_comments(cls, source_code: str, preserve_natspec: bool = False) -> str:
        """
        Strips single-line (//) and multi-line (/* */) comments from Solidity code
        while preserving string and character literals.
        If preserve_natspec is True, retains /// and /** ... */ docstrings.
        """
        # Tokenizer state machine regex: matches strings OR comments
        # Group 1: strings ("..." or '...')
        # Group 2: comments (//... or /*...*/)
        pattern = re.compile(
            r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(/\*[\s\S]*?\*/|//[^\r\n]*)'
        )

        def _replacer(match):
            # If string literal matched, keep it intact
            if match.group(1):
                return match.group(1)
            comment = match.group(2)
            # If preserving NatSpec docstrings
            if preserve_natspec:
                if comment.startswith("///") or comment.startswith("/**"):
                    return comment
            # If regular comment matched, replace with a single space or newline
            if comment.startswith("//"):
                return ""
            else:
                # Multi-line comment: keep newlines to preserve line count / spacing
                newlines = comment.count("\n")
                return "\n" * newlines if newlines > 0 else " "

        cleaned = pattern.sub(_replacer, source_code)
        # Collapse excessive blank lines
        cleaned = re.sub(r'\n\s*\n\s*\n+', '\n\n', cleaned)
        return cleaned.strip()

    @classmethod
    def unpack_etherscan_source(cls, raw_source: str) -> Tuple[str, Dict[str, str]]:
        """
        Unpacks Etherscan source code string, which can be:
        - Plain raw Solidity code
        - Standard-JSON format wrapped in double curly braces: '{{ ... }}'
        - Direct JSON map of filenames to sources
        Returns: (aggregated_code, dict_of_files)
        """
        raw_source = raw_source.strip()
        files = {}

        # Handle Etherscan double curly braces format {{ "sources": { ... } }}
        if raw_source.startswith("{{") and raw_source.endswith("}}"):
            raw_source = raw_source[1:-1]

        if (raw_source.startswith("{") and raw_source.endswith("}")) or (raw_source.startswith("[") and raw_source.endswith("]")):
            try:
                parsed = json.loads(raw_source)
                if isinstance(parsed, dict):
                    # Check for standard Solidity compiler JSON input: { "sources": { "File.sol": { "content": "..." } } }
                    if "sources" in parsed and isinstance(parsed["sources"], dict):
                        for filename, data in parsed["sources"].items():
                            if isinstance(data, dict) and "content" in data:
                                files[filename] = data["content"]
                            elif isinstance(data, str):
                                files[filename] = data
                    else:
                        # Direct mapping: { "File.sol": { "content": "..." } } or { "File.sol": "..." }
                        for filename, data in parsed.items():
                            if isinstance(data, dict) and "content" in data:
                                files[filename] = data["content"]
                            elif isinstance(data, str):
                                files[filename] = data
            except json.JSONDecodeError:
                pass

        if files:
            # Aggregate all .sol files with demarcation comments
            aggregated_parts = []
            for fname, content in files.items():
                aggregated_parts.append(f"// File: {fname}\n{content}")
            return "\n\n".join(aggregated_parts), files

        return raw_source, {"main.sol": raw_source}

    @classmethod
    def strip_zero_width_chars(cls, text: str) -> str:
        """
        Removes invisible zero-width and control characters used by attackers
        to bypass pattern matching (e.g. \u200b, \u200c, \u200d, \ufeff).
        """
        # Zero-width spaces, joiners, non-joiners, BOM, and soft hyphens
        zero_width_pattern = re.compile(r'[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]')
        return zero_width_pattern.sub("", text)

    @classmethod
    def neutralize_prompt_injections(cls, text: str) -> Tuple[str, int]:
        """
        Detects and strips out prompt injection attempts from the text.
        Hardened against zero-width character and invisible unicode obfuscation.
        Returns: (sanitized_text, number_of_detections)
        """
        normalized_text = cls.strip_zero_width_chars(text)
        sanitized = normalized_text
        total_detections = 0

        for pat in cls.PROMPT_INJECTION_PATTERNS:
            regex = re.compile(pat)
            matches = regex.findall(sanitized)
            if matches:
                total_detections += len(matches)
                sanitized = regex.sub("[SANITIZED_INJECTION_ATTEMPT]", sanitized)

        return sanitized, total_detections

    @classmethod
    def extract_structural_metadata(cls, clean_solidity: str) -> Dict[str, Any]:
        """
        Extracts compiler version, primary contract name, imports,
        state-changing functions (public/external), and raw assembly flag.
        """
        # Compiler version / pragma
        pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", clean_solidity)
        compiler_version = pragma_match.group(1).strip() if pragma_match else None

        # Imports
        imports = re.findall(r'import\s+(?:[^;]+);', clean_solidity)
        imports_count = len(imports)

        # Primary Contract Name: prioritize actual 'contract' definitions over interfaces and libraries
        actual_contracts = re.findall(r'\bcontract\s+([A-Za-z0-9_]+)', clean_solidity)
        all_declarations = re.findall(r'\b(?:contract|interface|library)\s+([A-Za-z0-9_]+)', clean_solidity)

        if actual_contracts:
            primary_contract_name = actual_contracts[-1]
        elif all_declarations:
            primary_contract_name = all_declarations[-1]
        else:
            primary_contract_name = None

        # Has raw assembly
        has_raw_assembly = bool(re.search(r'\bassembly\s*(?:"[^"]*")?\s*\{', clean_solidity))

        # Public/External state-changing functions
        # Matches: function name(...) [visibility: public|external]
        # Also matches Solidity >=0.6.0 receive() and fallback()
        func_pattern = re.compile(
            r'\bfunction\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*([^{;]*)',
            re.MULTILINE
        )

        state_changing_funcs = []
        for match in func_pattern.finditer(clean_solidity):
            name = match.group(1)
            params = match.group(2).strip()
            modifiers = match.group(3)

            is_public_or_external = bool(re.search(r'\b(public|external)\b', modifiers))
            is_read_only = bool(re.search(r'\b(view|pure)\b', modifiers))

            if is_public_or_external and not is_read_only:
                # Clean params: just types or simplified signature
                param_types = [p.strip().split()[0] for p in params.split(',') if p.strip()]
                sig = f"{name}({','.join(param_types)})"
                if sig not in state_changing_funcs:
                    state_changing_funcs.append(sig)

        # Check for receive() and fallback() handlers (Solidity >= 0.6.0)
        if re.search(r'\breceive\s*\(\s*\)\s*external\s+payable', clean_solidity):
            if "receive()" not in state_changing_funcs:
                state_changing_funcs.append("receive()")

        fallback_match = re.search(r'\bfallback\s*\(\s*([^)]*)\)\s*external', clean_solidity)
        if fallback_match:
            params = fallback_match.group(1).strip()
            sig = f"fallback({params})" if params else "fallback()"
            if sig not in state_changing_funcs:
                state_changing_funcs.append(sig)

        return {
            "primary_contract_name": primary_contract_name,
            "compiler_version": compiler_version,
            "imports_count": imports_count,
            "state_changing_functions": state_changing_funcs,
            "has_raw_assembly": has_raw_assembly
        }

    @classmethod
    def process_contract_source(
        cls,
        raw_source: str,
        target_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full Layer 1 Ingestion Pipeline for Smart Contract Source Code.
        Outputs exact Layer 1 Schema.
        """
        input_size_bytes = len(raw_source.encode("utf-8"))

        # Step 1: Unpack multi-file Etherscan format
        unpacked_code, _ = cls.unpack_etherscan_source(raw_source)

        # Step 2: Detect any prompt injections in raw input (including comments/docstrings)
        _, raw_injection_count = cls.neutralize_prompt_injections(unpacked_code)

        # Step 3: Strip comments safely
        clean_code = cls.strip_comments(unpacked_code)

        # Step 4: Detect and neutralize any remaining prompt injections in code strings
        clean_code, remaining_injection_count = cls.neutralize_prompt_injections(clean_code)
        total_injections = max(raw_injection_count, remaining_injection_count)

        # Step 5: Extract structural metadata
        metadata = cls.extract_structural_metadata(clean_code)

        iso_timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "status": "SUCCESS",
            "ingestion_metadata": {
                "source_type": "CONTRACT_SOURCE_CODE",
                "timestamp_processed": iso_timestamp,
                "input_size_bytes": input_size_bytes,
                "sanitization_performed": True
            },
            "extracted_data": {
                "target_address": target_address or "0x0000000000000000000000000000000000000000",
                "contract_metadata": {
                    "primary_contract_name": metadata["primary_contract_name"],
                    "compiler_version": metadata["compiler_version"],
                    "imports_count": metadata["imports_count"]
                },
                "function_selector": None,
                "cleaned_payload": clean_code,
                "structural_summary": {
                    "state_changing_functions": metadata["state_changing_functions"],
                    "has_raw_assembly": metadata["has_raw_assembly"],
                    "detected_prompt_injection_attempts": total_injections
                }
            },
            "pipeline_routing": {
                "recommended_downstream_engine": "LLM_SECURITY_AUDITOR"
            }
        }

    @classmethod
    def process_mempool_transaction(
        cls,
        raw_tx: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Full Layer 1 Ingestion Pipeline for Mempool Transaction Payloads.
        Outputs exact Layer 1 Schema.
        """
        raw_input = raw_tx.get("input") or raw_tx.get("data") or "0x"
        if not raw_input.startswith("0x"):
            raw_input = "0x" + raw_input

        input_size_bytes = len(raw_input) // 2

        # Extract function selector: 4 bytes (8 hex characters following '0x')
        function_selector = None
        if len(raw_input) >= 10:  # 0x + 8 hex chars
            function_selector = raw_input[:10].lower()

        target_address = raw_tx.get("to")
        if not target_address:
            target_address = "0x0000000000000000000000000000000000000000 (Contract Creation)"

        iso_timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "status": "SUCCESS",
            "ingestion_metadata": {
                "source_type": "MEMPOOL_TRANSACTION",
                "timestamp_processed": iso_timestamp,
                "input_size_bytes": input_size_bytes,
                "sanitization_performed": True
            },
            "extracted_data": {
                "target_address": target_address,
                "contract_metadata": {
                    "primary_contract_name": None,
                    "compiler_version": None,
                    "imports_count": 0
                },
                "function_selector": function_selector,
                "cleaned_payload": raw_input,
                "structural_summary": {
                    "state_changing_functions": [],
                    "has_raw_assembly": False,
                    "detected_prompt_injection_attempts": 0
                }
            },
            "pipeline_routing": {
                "recommended_downstream_engine": "ALGORITHMIC_PATTERN_MATCHER"
            }
        }

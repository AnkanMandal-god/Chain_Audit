"""
Layer 2: Hex Engine and Calldata Parser.

Performs:
- Function selector extraction (first 4 bytes / 8 hex characters after 0x)
- Calldata parameter segmentation
- Classification into ETH_TRANSFER, CONTRACT_CREATION, STANDARD_CALL, SUSPICIOUS_DRAIN
- Known EVM function signature resolution and risk scoring
"""
import re
from typing import Dict, Any, Optional


class HexEngine:
    # Common function signatures (4-byte selectors)
    SIGNATURE_REGISTRY = {
        # Standard Transfers & Approvals
        "0xa9059cbb": {"name": "transfer(address,uint256)", "category": "ERC20", "risk_level": "LOW"},
        "0x095ea7b3": {"name": "approve(address,uint256)", "category": "ERC20", "risk_level": "LOW"},
        "0x23b872dd": {"name": "transferFrom(address,address,uint256)", "category": "ERC20", "risk_level": "LOW"},
        "0x70a08231": {"name": "balanceOf(address)", "category": "ERC20", "risk_level": "INFO"},

        # DeFi Swaps & Liquidity
        "0x38ed1739": {"name": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)", "category": "DEX", "risk_level": "LOW"},
        "0x7ff36ab5": {"name": "swapExactETHForTokens(uint256,address[],address,uint256)", "category": "DEX", "risk_level": "LOW"},
        "0x18cbafe5": {"name": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)", "category": "DEX", "risk_level": "LOW"},
        "0xd0e30db0": {"name": "deposit()", "category": "WETH/Vault", "risk_level": "LOW"},
        "0x2e1a7d4d": {"name": "withdraw(uint256)", "category": "WETH/Vault", "risk_level": "MEDIUM"},

        # Flash Loans & High Impact Actions
        "0x5c11d795": {"name": "flashLoan(address,address,uint256,bytes)", "category": "FLASH_LOAN", "risk_level": "MEDIUM"},
        "0xab9c4b5d": {"name": "executeOperation(address,uint256,uint256,address,bytes)", "category": "FLASH_LOAN", "risk_level": "MEDIUM"},

        # Governance & Admin Privileges
        "0xf2fde38b": {"name": "transferOwnership(address)", "category": "ACCESS_CONTROL", "risk_level": "MEDIUM"},
        "0x79ba5097": {"name": "acceptOwnership()", "category": "ACCESS_CONTROL", "risk_level": "LOW"},
        "0x3659cfe6": {"name": "upgradeTo(address)", "category": "PROXY_UPGRADE", "risk_level": "HIGH"},
        "0x4f1ee3d0": {"name": "upgradeToAndCall(address,bytes)", "category": "PROXY_UPGRADE", "risk_level": "HIGH"},

        # Critical / Emergency / Suspicious Functions
        "0x54f3d9b4": {"name": "emergencyDrain()", "category": "DRAIN_EXPLOIT", "risk_level": "CRITICAL"},
        "0x82c0705d": {"name": "drainFunds(address)", "category": "DRAIN_EXPLOIT", "risk_level": "CRITICAL"},
        "0x41e0a294": {"name": "destroy()", "category": "SELFDESTRUCT", "risk_level": "CRITICAL"},
    }

    @classmethod
    def decode_calldata_params(cls, selector: str, calldata_hex: str) -> Optional[Dict[str, Any]]:
        """
        Decodes common ABI-encoded calldata parameters (e.g., ERC20 transfers, approvals).
        """
        if not calldata_hex or len(calldata_hex) < 64:
            return None

        try:
            # ERC20 transfer(address,uint256) or approve(address,uint256)
            if selector in ("0xa9059cbb", "0x095ea7b3") and len(calldata_hex) >= 128:
                addr_chunk = calldata_hex[:64]
                val_chunk = calldata_hex[64:128]
                recipient = "0x" + addr_chunk[24:]
                val_int = int(val_chunk, 16)
                param_name = "recipient" if selector == "0xa9059cbb" else "spender"
                is_infinite = val_int >= (2**256 - 1) or val_int > 10**32

                return {
                    param_name: recipient,
                    "raw_amount": str(val_int),
                    "is_infinite_approval": is_infinite if selector == "0x095ea7b3" else False
                }

            # ERC20 transferFrom(address,address,uint256)
            elif selector == "0x23b872dd" and len(calldata_hex) >= 192:
                from_addr = "0x" + calldata_hex[:64][24:]
                to_addr = "0x" + calldata_hex[64:128][24:]
                val_int = int(calldata_hex[128:192], 16)
                return {
                    "from": from_addr,
                    "to": to_addr,
                    "raw_amount": str(val_int)
                }
        except Exception:
            return None
        return None

    @classmethod
    def normalize_hex_payload(cls, raw_input: str) -> str:
        """
        Validates, normalizes, and byte-aligns raw hex payloads.
        Handles missing 0x prefix, non-hex characters, and odd-length hex strings.
        """
        if not raw_input:
            return "0x"
        raw_input = raw_input.strip()
        hex_data = raw_input[2:] if raw_input.startswith(("0x", "0X")) else raw_input

        # Filter to valid hex digits
        valid_hex = re.sub(r'[^0-9a-fA-F]', '', hex_data)
        # Byte alignment (even length)
        if len(valid_hex) % 2 != 0:
            valid_hex = "0" + valid_hex
        return "0x" + valid_hex.lower()

    @classmethod
    def parse_transaction(cls, tx: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses raw mempool transaction bytecode, extracts selector,
        decodes ABI calldata parameters, and classifies the interaction.
        """
        raw_input = cls.normalize_hex_payload(tx.get("input") or tx.get("data") or "0x")

        to_addr = tx.get("to")
        value_raw = tx.get("value", "0x0")
        gas_raw = tx.get("gas", "0x0")
        gas_price_raw = tx.get("gasPrice", "0x0")

        # Convert hex values safely
        try:
            value_wei = int(value_raw, 16) if isinstance(value_raw, str) else int(value_raw)
        except (ValueError, TypeError):
            value_wei = 0

        try:
            gas_limit = int(gas_raw, 16) if isinstance(gas_raw, str) else int(gas_raw)
        except (ValueError, TypeError):
            gas_limit = 0

        # EIP-1559 and Legacy Gas Price Resolution
        max_fee_raw = tx.get("maxFeePerGas")
        max_priority_raw = tx.get("maxPriorityFeePerGas")

        try:
            max_fee = int(max_fee_raw, 16) if isinstance(max_fee_raw, str) else int(max_fee_raw or 0)
        except (ValueError, TypeError):
            max_fee = 0

        try:
            max_priority = int(max_priority_raw, 16) if isinstance(max_priority_raw, str) else int(max_priority_raw or 0)
        except (ValueError, TypeError):
            max_priority = 0

        try:
            legacy_gas_price = int(gas_price_raw, 16) if isinstance(gas_price_raw, str) else int(gas_price_raw or 0)
        except (ValueError, TypeError):
            legacy_gas_price = 0

        effective_gas_price = legacy_gas_price if legacy_gas_price > 0 else max_fee

        # Classification logic
        payload_classification = "STANDARD_CALL"
        selector = None
        selector_info = None
        calldata_params = ""
        decoded_params = None

        if not to_addr or to_addr in ("0x", "0x0000000000000000000000000000000000000000"):
            payload_classification = "CONTRACT_CREATION"
        elif raw_input in ("0x", ""):
            payload_classification = "ETH_TRANSFER"
        else:
            if len(raw_input) >= 10:
                selector = raw_input[:10].lower()
                calldata_params = raw_input[10:]
                selector_info = cls.SIGNATURE_REGISTRY.get(selector)
                if selector_info and selector_info["risk_level"] == "CRITICAL":
                    payload_classification = "SUSPICIOUS_HIGH_RISK_CALL"
                decoded_params = cls.decode_calldata_params(selector, calldata_params)

        # Check for abnormal gas setup (e.g. extremely high gas price typical of frontrunning/MEV)
        high_gas_anomaly = effective_gas_price > 100 * 10**9  # > 100 Gwei

        return {
            "tx_hash": tx.get("hash"),
            "sender": tx.get("from", "0x0"),
            "target": to_addr,
            "value_wei": value_wei,
            "value_eth": value_wei / 10**18,
            "gas_limit": gas_limit,
            "gas_price_gwei": effective_gas_price / 10**9,
            "max_fee_per_gas_gwei": (max_fee / 10**9) if max_fee > 0 else None,
            "max_priority_fee_gwei": (max_priority / 10**9) if max_priority > 0 else None,
            "is_eip1559": bool(max_fee_raw is not None or max_priority_raw is not None),
            "high_gas_anomaly": high_gas_anomaly,
            "payload_classification": payload_classification,
            "function_selector": selector,
            "signature_info": selector_info,
            "decoded_parameters": decoded_params,
            "calldata_length_bytes": max(0, (len(raw_input) - 2) // 2),
            "calldata_params_hex": calldata_params[:64] + ("..." if len(calldata_params) > 64 else "")
        }

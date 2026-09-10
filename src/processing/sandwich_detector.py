"""
Layer 2: Algorithmic MEV Sandwich Attack Detector.

Tracks pending transactions per liquidity pool or router over a sliding time
window T_sandwich (e.g., 5 seconds) to identify front-run, victim, and back-run
transaction clusters characteristic of MEV sandwich attacks.
"""
import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Tuple


class SandwichDetector:
    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = window_seconds
        # pool_address -> deque of {tx_hash, sender, gas_price, timestamp, classification}
        self.pool_windows: Dict[str, deque] = defaultdict(deque)

    def record_and_evaluate(self, tx: Dict[str, Any], timestamp: Optional[float] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Records a transaction against its target pool and evaluates if it completes
        or constitutes an MEV sandwich attack sequence.

        Returns: (is_sandwich_flagged, details_dict)
        """
        target = (tx.get("target") or tx.get("to") or "").lower()
        if not target or target in ("0x0", "0x0000000000000000000000000000000000000000"):
            return False, None

        now = timestamp if timestamp is not None else time.time()
        q = self.pool_windows[target]

        # Prune transactions older than window_seconds
        cutoff = now - self.window_seconds
        while q and q[0]["timestamp"] < cutoff:
            q.popleft()

        sender = (tx.get("sender") or tx.get("from") or "0x0").lower()
        gas_price = tx.get("gas_price_gwei") or 0.0
        tx_hash = tx.get("tx_hash") or tx.get("hash") or "0x0"
        selector = tx.get("function_selector") or "0x"

        # Check for sandwich back-run match:
        # Looking for a prior front-run by the SAME sender with HIGHER gas price,
        # and at least one intermediate transaction by a DIFFERENT sender (the victim).
        if len(q) >= 2:
            frontrun_candidate = None
            victim_candidate = None

            for past_tx in list(q):
                if past_tx["sender"] == sender and past_tx["gas_price"] >= gas_price:
                    frontrun_candidate = past_tx
                elif frontrun_candidate is not None and past_tx["sender"] != sender:
                    victim_candidate = past_tx

            if frontrun_candidate and victim_candidate:
                sandwich_alert = {
                    "attack_type": "MEV_SANDWICH_ATTACK",
                    "target_pool": target,
                    "frontrun_tx": frontrun_candidate["tx_hash"],
                    "frontrun_gas_gwei": frontrun_candidate["gas_price"],
                    "victim_tx": victim_candidate["tx_hash"],
                    "victim_sender": victim_candidate["sender"],
                    "backrun_tx": tx_hash,
                    "backrun_gas_gwei": gas_price,
                    "attacker_address": sender,
                    "detection_reason": (
                        f"Detected front-run ({frontrun_candidate['tx_hash'][:10]}... @ {frontrun_candidate['gas_price']} Gwei) "
                        f"and back-run ({tx_hash[:10]}... @ {gas_price} Gwei) by attacker {sender[:10]}... "
                        f"surrounding victim {victim_candidate['sender'][:10]}... in pool {target[:10]}..."
                    )
                }
                # Record current tx into queue
                q.append({
                    "tx_hash": tx_hash,
                    "sender": sender,
                    "gas_price": gas_price,
                    "timestamp": now,
                    "selector": selector
                })
                return True, sandwich_alert

        # Enqueue current transaction
        q.append({
            "tx_hash": tx_hash,
            "sender": sender,
            "gas_price": gas_price,
            "timestamp": now,
            "selector": selector
        })

        return False, None

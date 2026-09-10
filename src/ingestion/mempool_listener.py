"""
Layer 1: Live Mempool Listener with WebSockets and Auto-Reconnect.

Subscribes to Ethereum pending transactions via:
- Real WebSocket connection (`eth_subscribe` / `newPendingTransactions`)
- Simulated stream for offline testing, burst attack demonstrations, and evaluation.
"""
import asyncio
import json
import logging
import random
import time
from typing import AsyncGenerator, Dict, Any, Optional
import websockets
from config.settings import settings

import httpx

logger = logging.getLogger(__name__)


class MempoolListener:
    def __init__(
        self,
        ws_url: Optional[str] = None,
        http_rpc_url: Optional[str] = None,
        reconnect_delay_base: float = 1.0,
        reconnect_delay_max: float = 30.0
    ):
        self.ws_url = ws_url or settings.eth_rpc_ws_url
        self.http_rpc_url = http_rpc_url or settings.eth_rpc_http_url
        self.reconnect_delay_base = reconnect_delay_base
        self.reconnect_delay_max = reconnect_delay_max
        self._running = False

    async def fetch_transaction_by_hash(
        self,
        client: httpx.AsyncClient,
        tx_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Queries JSON-RPC endpoint for full transaction details given a tx hash."""
        if not self.http_rpc_url or not tx_hash:
            return None
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash]
        }
        try:
            res = await client.post(self.http_rpc_url, json=payload, timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                return data.get("result")
        except Exception as e:
            logger.debug(f"Could not fetch tx {tx_hash} details: {e}")
        return None

    async def listen_live(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Connects to Ethereum RPC node via WebSockets and streams pending transactions.
        Resolves full transaction details (from, to, input, gas) when available.
        Features automatic reconnection with exponential backoff.
        """
        self._running = True
        delay = self.reconnect_delay_base
        consecutive_failures = 0
        max_failures = 3

        while self._running:
            try:
                logger.info(f"Connecting to Ethereum Mempool WebSocket at {self.ws_url}...")
                async with websockets.connect(self.ws_url) as ws, httpx.AsyncClient(timeout=10.0) as http_client:
                    delay = self.reconnect_delay_base  # reset delay on successful connection
                    consecutive_failures = 0
                    logger.info("Connected to Mempool WebSocket. Subscribing to pending transactions...")

                    # Attempt alchemy_pendingTransactions if Alchemy URL, else newPendingTransactions
                    sub_method = "alchemy_pendingTransactions" if "alchemy" in self.ws_url.lower() else "newPendingTransactions"
                    subscribe_req = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_subscribe",
                        "params": [sub_method]
                    }
                    await ws.send(json.dumps(subscribe_req))
                    sub_response = await ws.recv()
                    logger.info(f"Subscription confirmed: {sub_response}")

                    while self._running:
                        message = await ws.recv()
                        data = json.loads(message)
                        if "params" in data and "result" in data["params"]:
                            item = data["params"]["result"]

                            if isinstance(item, dict):
                                # Full tx object provided by provider (e.g. Alchemy or custom RPC)
                                tx_hash = item.get("hash")
                                yield {
                                    "hash": tx_hash,
                                    "to": item.get("to"),
                                    "from": item.get("from") or "0x0",
                                    "input": item.get("input") or item.get("data") or "0x",
                                    "value": item.get("value", "0x0"),
                                    "gas": item.get("gas", "0x0"),
                                    "gasPrice": item.get("gasPrice", "0x0"),
                                    "maxFeePerGas": item.get("maxFeePerGas"),
                                    "maxPriorityFeePerGas": item.get("maxPriorityFeePerGas"),
                                    "timestamp": time.time()
                                }
                            elif isinstance(item, str):
                                # Standard eth_subscribe hash notification
                                tx_hash = item
                                full_tx = await self.fetch_transaction_by_hash(http_client, tx_hash)

                                if full_tx and isinstance(full_tx, dict):
                                    yield {
                                        "hash": tx_hash,
                                        "to": full_tx.get("to"),
                                        "from": full_tx.get("from") or "0x0",
                                        "input": full_tx.get("input") or full_tx.get("data") or "0x",
                                        "value": full_tx.get("value", "0x0"),
                                        "gas": full_tx.get("gas", "0x0"),
                                        "gasPrice": full_tx.get("gasPrice", "0x0"),
                                        "maxFeePerGas": full_tx.get("maxFeePerGas"),
                                        "maxPriorityFeePerGas": full_tx.get("maxPriorityFeePerGas"),
                                        "timestamp": time.time()
                                    }
                                else:
                                    yield {
                                        "hash": tx_hash,
                                        "to": None,
                                        "input": "0x",
                                        "from": "0x0",
                                        "timestamp": time.time()
                                    }

            except (websockets.ConnectionClosedError, websockets.WebSocketException, OSError, Exception) as exc:
                if not self._running:
                    break
                consecutive_failures += 1
                logger.warning(f"Mempool WebSocket disconnected: {exc}. Reconnecting in {delay:.1f}s (Attempt {consecutive_failures}/{max_failures})...")

                if consecutive_failures >= max_failures:
                    yield {
                        "_error": True,
                        "error": f"Failed to connect to Ethereum RPC WebSocket at {self.ws_url}",
                        "details": f"Connection error: {exc}. Reached {max_failures} consecutive connection failures."
                    }
                    break

                await asyncio.sleep(delay)
                delay = min(delay * 2, self.reconnect_delay_max)

    def stop(self):
        self._running = False



class SimulatedMempoolStream:
    """
    Generates synthetic mempool transaction streams for offline testing,
    including standard transfers, Uniswap swaps, high-frequency bot spam,
    and suspicious emergency drain calls.
    """
    SAMPLE_TARGETS = [
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
        "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",  # Uniswap Universal Router
        "0xBA12222222228d8Ba531E7843219301604925516",  # Balancer Vault
    ]

    SAMPLE_SELECTORS = [
        ("0xa9059cbb", "transfer(address,uint256)"),
        ("0x095ea7b3", "approve(address,uint256)"),
        ("0x38ed1739", "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
        ("0xd0e30db0", "deposit()"),
        ("0x2e1a7d4d", "withdraw(uint256)"),
        ("0x70a08231", "balanceOf(address)"),
        ("0x", "Standard ETH Transfer"),
        ("0x54f3d9b4", "emergencyDrain() [SUSPICIOUS]"),
        ("0x82c0705d", "drainFunds(address) [CRITICAL]"),
        ("0x5c11d795", "flashLoan(address,address,uint256,bytes)"),
    ]

    SAMPLE_SENDERS = [
        "0x1111111254EEB25477B68fb85Ed929f73A960582",  # 1inch Bot
        "0x6b175474e89094c44da98b954eedeac495271d0f",  # Regular Trader
        "0x999999cf1046e68e36E1aA2E0E07105eDDD1f08E",  # High-Frequency MEV Bot
        "0xdeadbeef00000000000000000000000000000000",  # Malicious Attacker
    ]

    @classmethod
    async def stream_synthetic(
        cls,
        count: int = 20,
        interval: float = 0.3,
        simulate_burst: bool = True
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Yields realistic mock mempool transactions.
        If simulate_burst is True, simulates a high-frequency sandwich bot spamming 8 transactions in < 2 seconds.
        """
        produced = 0
        while count <= 0 or produced < count:
            produced += 1

            # Inject burst scenario around transaction #6
            if simulate_burst and produced == 6:
                burst_sender = "0x999999cf1046e68e36E1aA2E0E07105eDDD1f08E"
                for i in range(7):
                    yield {
                        "hash": f"0xburst{produced}{i}{random.randint(1000, 9999):04x}",
                        "from": burst_sender,
                        "to": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
                        "value": "0x0",
                        "gas": "0x493e0",
                        "gasPrice": "0xba43b7400",
                        "input": "0x38ed1739" + "00" * 32,
                        "timestamp": time.time()
                    }
                    await asyncio.sleep(0.05)

            sender = random.choice(cls.SAMPLE_SENDERS)
            target = random.choice(cls.SAMPLE_TARGETS)
            selector, _ = random.choice(cls.SAMPLE_SELECTORS)

            # Generate dummy calldata parameters if selector present
            payload_data = selector
            if selector != "0x":
                payload_data += "".join([f"{random.randint(0, 255):02x}" for _ in range(32)])

            tx = {
                "hash": f"0x{random.randint(1, 10**16):016x}{random.randint(1, 10**16):016x}",
                "from": sender,
                "to": target,
                "value": hex(random.choice([0, 10**16, 5 * 10**17])),
                "gas": hex(random.randint(21000, 300000)),
                "gasPrice": hex(random.randint(20 * 10**9, 80 * 10**9)),
                "input": payload_data,
                "timestamp": time.time()
            }

            yield tx
            await asyncio.sleep(interval)

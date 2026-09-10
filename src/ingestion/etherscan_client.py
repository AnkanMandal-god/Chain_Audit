"""
Layer 1: Etherscan REST Client with Token Bucket Rate Limiter and Backoff.

Ensures:
- Strictly <= 5 requests/second (Etherscan standard API limit)
- Exponential backoff with jitter on 429 Too Many Requests
- Automatic error handling for unverified / invalid contract addresses
"""
import time
import asyncio
import random
import logging
from typing import Dict, Any, Optional
import httpx
from config.settings import settings

logger = logging.getLogger(__name__)


class TokenBucketRateLimiter:
    """
    Token Bucket rate limiter for strict API rate control.
    Default: capacity = 5.0 tokens, refill_rate = 5.0 tokens/second.
    """
    def __init__(self, capacity: float = 5.0, refill_rate: float = 5.0):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.last_refill = now

            # Refill tokens
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

            if self.tokens < 1.0:
                # Wait for token replenishment
                wait_time = (1.0 - self.tokens) / self.refill_rate
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
                self.last_refill = time.monotonic()
            else:
                self.tokens -= 1.0


class EtherscanClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        chain: str = "ethereum",
        rate_limit_per_sec: float = 5.0
    ):
        self.chain = (chain or "ethereum").lower()
        chain_cfg = settings.get_chain_config(self.chain) if self.chain in settings.chains else None
        default_base_url = chain_cfg["api_url"] if chain_cfg else settings.etherscan_base_url

        self.api_key = api_key or settings.etherscan_api_key
        self.base_url = base_url or default_base_url
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=rate_limit_per_sec,
            refill_rate=rate_limit_per_sec
        )

    async def get_contract_source_code(
        self,
        contract_address: str,
        max_retries: int = 4
    ) -> Dict[str, Any]:
        """
        Fetches verified contract source code from Etherscan getsourcecode endpoint.
        Implements rate limiting and exponential backoff with jitter.
        """
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": contract_address,
            "apikey": self.api_key
        }

        retries = 0
        backoff_delay = 1.0

        async with httpx.AsyncClient(timeout=8.0) as client:
            while retries <= max_retries:
                # Enforce token bucket rate limit
                await self.rate_limiter.acquire()

                try:
                    response = await client.get(self.base_url, params=params)

                    if response.status_code == 429:
                        # Rate limit hit: exponential backoff + jitter
                        retries += 1
                        jitter = random.uniform(0.1, 0.5)
                        sleep_time = backoff_delay + jitter
                        logger.warning(
                            f"[429 Rate Limit] Retrying after {sleep_time:.2f}s "
                            f"(attempt {retries}/{max_retries})"
                        )
                        await asyncio.sleep(sleep_time)
                        backoff_delay *= 2
                        continue

                    response.raise_for_status()
                    data = response.json()

                    if data.get("status") != "1" or not data.get("result"):
                        error_msg = data.get("message") or data.get("result") or "Contract not verified or not found"
                        return {
                            "success": False,
                            "error": str(error_msg),
                            "address": contract_address,
                            "source_code": None
                        }

                    result = data["result"][0]
                    raw_source = result.get("SourceCode", "")
                    contract_name = result.get("ContractName", "")
                    compiler_version = result.get("CompilerVersion", "")

                    if not raw_source:
                        return {
                            "success": False,
                            "error": "Contract bytecode exists on-chain, but its source code has not been verified on the block explorer.",
                            "address": contract_address,
                            "source_code": None
                        }

                    return {
                        "success": True,
                        "address": contract_address,
                        "contract_name": contract_name,
                        "compiler_version": compiler_version,
                        "source_code": raw_source,
                        "raw_result": result
                    }

                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    retries += 1
                    err_type = "Connection/Handshake Timeout" if isinstance(exc, httpx.ConnectTimeout) else type(exc).__name__
                    if retries > max_retries:
                        return {
                            "success": False,
                            "error": (
                                f"Failed to connect to block explorer ({self.base_url}) after {max_retries} retries: {err_type}. "
                                f"Check your internet connection, verify your API key, or test using a local .sol contract file."
                            ),
                            "address": contract_address,
                            "source_code": None
                        }
                    jitter = random.uniform(0.1, 0.4)
                    await asyncio.sleep(backoff_delay + jitter)
                    backoff_delay *= 2

        return {
            "success": False,
            "error": "Exceeded maximum retry attempts without receiving response from explorer.",
            "address": contract_address,
            "source_code": None
        }

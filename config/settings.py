"""
Configuration settings for Chain-Mind Auditor.
"""
import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseModel):
    # Etherscan Configuration
    etherscan_api_key: str = os.getenv("ETHERSCAN_API_KEY", "")
    etherscan_base_url: str = os.getenv("ETHERSCAN_BASE_URL", "https://api.etherscan.io/api")
    etherscan_rate_limit_per_sec: float = 5.0  # Max 5 requests per second

    # Mempool / RPC WebSocket and HTTP Configuration
    eth_rpc_ws_url: str = os.getenv("ETH_RPC_WS_URL", "wss://ethereum-rpc.publicnode.com")
    eth_rpc_http_url: str = os.getenv("ETH_RPC_HTTP_URL", "https://ethereum.publicnode.com")
    ws_reconnect_delay_base: float = 1.0
    ws_reconnect_delay_max: float = 30.0

    # Ingestion Buffer
    buffer_max_size: int = 1000

    # Sliding Window Anomaly Detection Settings (DSA)
    sliding_window_seconds: float = 10.0  # Time window T
    anomaly_tx_threshold: int = 5         # More than N txs in T seconds flags an anomaly

    # LLM Settings
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "gemini-2.0-flash")

    # Multi-Chain Registry
    chains: dict = {
        "ethereum": {
            "name": "Ethereum Mainnet",
            "api_url": os.getenv("ETHERSCAN_BASE_URL", "https://api.etherscan.io/api"),
            "ws_rpc": os.getenv("ETH_RPC_WS_URL", "wss://ethereum-rpc.publicnode.com"),
            "http_rpc": os.getenv("ETH_RPC_HTTP_URL", "https://ethereum.publicnode.com")
        },
        "arbitrum": {
            "name": "Arbitrum One",
            "api_url": os.getenv("ARBISCAN_BASE_URL", "https://api.arbiscan.io/api"),
            "ws_rpc": os.getenv("ARB_RPC_WS_URL", "wss://arbitrum-one-rpc.publicnode.com"),
            "http_rpc": os.getenv("ARB_RPC_HTTP_URL", "https://arbitrum-one.publicnode.com")
        },
        "optimism": {
            "name": "Optimism Mainnet",
            "api_url": os.getenv("OPTIMISTIC_BASE_URL", "https://api-optimistic.etherscan.io/api"),
            "ws_rpc": os.getenv("OPT_RPC_WS_URL", "wss://optimism-rpc.publicnode.com"),
            "http_rpc": os.getenv("OPT_RPC_HTTP_URL", "https://optimism.publicnode.com")
        },
        "polygon": {
            "name": "Polygon PoS",
            "api_url": os.getenv("POLYGONSCAN_BASE_URL", "https://api.polygonscan.com/api"),
            "ws_rpc": os.getenv("POLYGON_RPC_WS_URL", "wss://polygon-bor-rpc.publicnode.com"),
            "http_rpc": os.getenv("POLYGON_RPC_HTTP_URL", "https://polygon-bor.publicnode.com")
        },
        "base": {
            "name": "Base Mainnet",
            "api_url": os.getenv("BASESCAN_BASE_URL", "https://api.basescan.org/api"),
            "ws_rpc": os.getenv("BASE_RPC_WS_URL", "wss://base-rpc.publicnode.com"),
            "http_rpc": os.getenv("BASE_RPC_HTTP_URL", "https://base.publicnode.com")
        }
    }

    def get_chain_config(self, chain_name: str) -> dict:
        key = (chain_name or "ethereum").lower()
        if key not in self.chains:
            raise ValueError(f"Unsupported chain: '{chain_name}'. Supported chains: {list(self.chains.keys())}")
        return self.chains[key]


settings = Settings()


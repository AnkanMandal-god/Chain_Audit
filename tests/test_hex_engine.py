"""Unit tests for Layer 2: Hex Engine and Function Selector Resolution."""
from src.processing.hex_engine import HexEngine


def test_erc20_transfer_selector():
    tx = {
        "hash": "0x123",
        "from": "0xaaa",
        "to": "0xbbb",
        "input": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "value": "0x0"
    }
    res = HexEngine.parse_transaction(tx)
    assert res["function_selector"] == "0xa9059cbb"
    assert res["payload_classification"] == "STANDARD_CALL"
    assert res["signature_info"]["name"] == "transfer(address,uint256)"


def test_suspicious_drain_selector():
    tx = {
        "hash": "0x456",
        "from": "0xattacker",
        "to": "0xtarget",
        "input": "0x54f3d9b4",
        "value": "0x0"
    }
    res = HexEngine.parse_transaction(tx)
    assert res["function_selector"] == "0x54f3d9b4"
    assert res["payload_classification"] == "SUSPICIOUS_HIGH_RISK_CALL"
    assert res["signature_info"]["risk_level"] == "CRITICAL"


def test_eth_transfer_classification():
    tx = {
        "hash": "0x789",
        "from": "0xalice",
        "to": "0xbob",
        "input": "0x",
        "value": "0xde0b6b3a7640000"
    }
    res = HexEngine.parse_transaction(tx)
    assert res["payload_classification"] == "ETH_TRANSFER"
    assert res["value_eth"] == 1.0


def test_contract_creation_classification():
    tx = {
        "hash": "0xabc",
        "from": "0xdeployer",
        "to": None,
        "input": "0x608060405234801561001057600080fd5b50",
        "value": "0x0"
    }
    res = HexEngine.parse_transaction(tx)
    assert res["payload_classification"] == "CONTRACT_CREATION"


def test_decode_erc20_transfer_params():
    # transfer(address to, uint256 amount)
    # to: 0x0000000000000000000000001234567890123456789012345678901234567890
    # amount: 1 ether (10**18 = 0x0de0b6b3a7640000)
    tx = {
        "hash": "0x123",
        "from": "0xaaa",
        "to": "0xbbb",
        "input": "0xa9059cbb00000000000000000000000012345678901234567890123456789012345678900000000000000000000000000000000000000000000000000de0b6b3a7640000",
        "value": "0x0"
    }
    res = HexEngine.parse_transaction(tx)
    params = res["decoded_parameters"]
    assert params is not None
    assert params["recipient"].lower() == "0x1234567890123456789012345678901234567890".lower()
    assert params["raw_amount"] == str(10**18)


def test_decode_infinite_approval():
    # approve(address spender, uint256 amount) with 2**256 - 1 (ffff...ffff)
    infinite_hex = "f" * 64
    tx = {
        "hash": "0x999",
        "from": "0xuser",
        "to": "0xtoken",
        "input": "0x095ea7b30000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d" + infinite_hex,
        "value": "0x0"
    }
    res = HexEngine.parse_transaction(tx)
    params = res["decoded_parameters"]
    assert params is not None
    assert params["spender"].lower() == "0x7a250d5630b4cf539739df2c5dacb4c659f2488d".lower()
    assert params["is_infinite_approval"] is True


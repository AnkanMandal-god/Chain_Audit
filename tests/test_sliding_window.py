"""Unit tests for Layer 2: Sliding Window Frequency Anomaly Counter."""
import time
from src.processing.sliding_window import SlidingWindowRateTracker


def test_sliding_window_normal_traffic():
    tracker = SlidingWindowRateTracker(window_seconds=10.0, threshold_count=5)
    sender = "0x1234567890abcdef1234567890abcdef12345678"

    # Send 3 transactions spaced out
    is_anom1, count1, _ = tracker.record_transaction(sender, timestamp=100.0)
    is_anom2, count2, _ = tracker.record_transaction(sender, timestamp=102.0)
    is_anom3, count3, _ = tracker.record_transaction(sender, timestamp=104.0)

    assert not is_anom1
    assert not is_anom2
    assert not is_anom3
    assert count3 == 3


def test_sliding_window_anomaly_burst():
    tracker = SlidingWindowRateTracker(window_seconds=10.0, threshold_count=5)
    sender = "0xbot000000000000000000000000000000000000"

    base_time = 1000.0
    for i in range(4):
        is_anom, count, _ = tracker.record_transaction(sender, timestamp=base_time + i * 0.2)
        assert not is_anom

    # 5th transaction in rapid succession should trigger anomaly
    is_anom_5, count_5, meta = tracker.record_transaction(sender, timestamp=base_time + 1.0)
    assert is_anom_5
    assert count_5 == 5
    assert "High frequency" in meta["anomaly_reason"]


def test_sliding_window_eviction():
    tracker = SlidingWindowRateTracker(window_seconds=5.0, threshold_count=3)
    sender = "0xuser00000000000000000000000000000000000"

    tracker.record_transaction(sender, timestamp=100.0)
    tracker.record_transaction(sender, timestamp=101.0)

    # Fast forward past window (100.0 and 101.0 should be evicted at t=107.0)
    is_anom, count, _ = tracker.record_transaction(sender, timestamp=107.0)
    assert not is_anom
    assert count == 1


def test_sliding_window_garbage_collection():
    tracker = SlidingWindowRateTracker(window_seconds=5.0, threshold_count=3)
    tracker.gc_interval = 5  # Trigger GC every 5 records for test

    # Record transactions from multiple unique addresses
    for i in range(10):
        tracker.record_transaction(f"0xaddr_{i}", timestamp=10.0)

    assert len(tracker.address_windows) == 10

    # Fast forward: all addresses expire, record from a new address until GC interval is hit (total 15)
    for _ in range(5):
        tracker.record_transaction("0xnew_active", timestamp=30.0)

    # All stale addresses should have been pruned by GC
    assert "0xaddr_0" not in tracker.address_windows
    assert "0xnew_active" in tracker.address_windows
    assert len(tracker.address_windows) == 1


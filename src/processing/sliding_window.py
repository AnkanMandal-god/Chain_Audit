"""
Layer 2: DSA In-Memory Sliding Window Frequency Counter.

Tracks transaction frequency per sender address over a configurable moving
time window T (e.g., 10 seconds). If an address submits more than N transactions
within T seconds, it is flagged as a high-frequency anomaly (potential MEV sandwich,
DDoS, or automated spam attack).

Data Structure:
- Hash map of address -> collections.deque([timestamp1, timestamp2, ...])
- Amortized O(1) eviction of expired timestamps from the front of the queue.
"""
import time
from collections import defaultdict, deque
from typing import Dict, Any, Tuple


class SlidingWindowRateTracker:
    def __init__(self, window_seconds: float = 10.0, threshold_count: int = 5):
        """
        :param window_seconds: Moving time window T in seconds.
        :param threshold_count: Number of transactions N in window T triggering an anomaly.
        """
        self.window_seconds = window_seconds
        self.threshold_count = threshold_count
        # address -> deque of timestamps
        self.address_windows: Dict[str, deque] = defaultdict(deque)
        self.total_records_seen: int = 0
        self.gc_interval: int = 250  # Run garbage collection every 250 records

    def prune_stale_addresses(self, current_time: float = None):
        """
        Garbage collection: removes address entries that have no active
        transactions within the sliding window, preventing unbounded memory growth.
        """
        now = current_time if current_time is not None else time.time()
        cutoff = now - self.window_seconds
        stale_keys = []

        for addr, q in self.address_windows.items():
            while q and q[0] < cutoff:
                q.popleft()
            if not q:
                stale_keys.append(addr)

        for addr in stale_keys:
            del self.address_windows[addr]

    def record_transaction(self, sender_address: str, timestamp: float = None) -> Tuple[bool, int, Dict[str, Any]]:
        """
        Records a transaction from sender_address at timestamp.
        Prunes entries older than (current_time - window_seconds).

        Returns:
            (is_anomalous, count_in_window, metadata)
        """
        now = timestamp if timestamp is not None else time.time()
        address = sender_address.lower() if sender_address else "0x0"
        self.total_records_seen += 1

        # Periodic garbage collection to maintain lean memory footprint
        if self.total_records_seen % self.gc_interval == 0:
            self.prune_stale_addresses(current_time=now)

        q = self.address_windows[address]

        # Evict timestamps outside the window T (O(1) amortized)
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()

        # Add current transaction timestamp
        q.append(now)
        count = len(q)

        # Flag if count exceeds threshold N
        is_anomalous = count >= self.threshold_count

        metadata = {
            "address": address,
            "count_in_window": count,
            "window_seconds": self.window_seconds,
            "threshold": self.threshold_count,
            "rate_per_second": round(count / self.window_seconds, 2) if self.window_seconds > 0 else 0,
            "is_anomalous": is_anomalous,
            "anomaly_reason": f"High frequency: {count} transactions in {self.window_seconds}s (threshold: {self.threshold_count})" if is_anomalous else "Normal transaction volume"
        }

        return is_anomalous, count, metadata

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics on active addresses being tracked."""
        now = time.time()
        cutoff = now - self.window_seconds
        active_senders = 0
        total_active_txs = 0

        for addr, q in list(self.address_windows.items()):
            while q and q[0] < cutoff:
                q.popleft()
            if q:
                active_senders += 1
                total_active_txs += len(q)

        return {
            "tracked_addresses": len(self.address_windows),
            "active_senders_in_window": active_senders,
            "total_active_txs_in_window": total_active_txs
        }

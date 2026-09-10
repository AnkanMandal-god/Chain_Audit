"""
Layer 1: Ingestion Buffer Queue with Backpressure Handling.

Manages an asynchronous FIFO queue between data ingestion (WebSockets / REST)
and the downstream processing engines, preventing memory spikes during high
network traffic or mempool transaction bursts.
"""
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class IngestionBufferQueue:
    def __init__(self, maxsize: int = 1000):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.dropped_count: int = 0
        self.processed_count: int = 0

    async def put(self, item: Dict[str, Any], block: bool = True, timeout: Optional[float] = 2.0) -> bool:
        """
        Pushes a normalized item into the buffer queue.
        If the queue is full and cannot accept items, drops or waits based on timeout
        to preserve system stability.
        """
        try:
            if block:
                await asyncio.wait_for(self.queue.put(item), timeout=timeout)
            else:
                self.queue.put_nowait(item)
            return True
        except (asyncio.QueueFull, asyncio.TimeoutError):
            self.dropped_count += 1
            logger.warning(
                f"[Backpressure Warning] Buffer queue full ({self.queue.qsize()}/{self.queue.maxsize}). "
                f"Dropped {self.dropped_count} incoming items."
            )
            return False

    async def get(self) -> Dict[str, Any]:
        """Retrieves the next normalized item from the buffer queue."""
        item = await self.queue.get()
        self.processed_count += 1
        return item

    def task_done(self):
        """Marks a previously enqueued task as completed."""
        self.queue.task_done()

    def size(self) -> int:
        """Returns the current queue depth."""
        return self.queue.qsize()

    def is_empty(self) -> bool:
        """Returns True if the queue is empty."""
        return self.queue.empty()

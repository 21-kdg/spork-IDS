"""Bucket primitives implementing CrowdSec detection concepts in Python."""
import time
from typing import Dict, List, Optional, Any, Tuple


class LeakyBucket:
    """
    Standard Leaky Bucket.
    Under certain conditions, events are poured into the bucket.
    One event leaks out of the bucket after each full `leakspeed_seconds` interval.
    When the bucket capacity is reached, it overflows.
    """

    def __init__(self, name: str, stack_key: str, capacity: int, leakspeed_seconds: float):
        self.name = name
        self.stack_key = stack_key
        self.capacity = max(1, capacity)
        self.leakspeed_seconds = max(0.1, leakspeed_seconds)
        self.current_drops: int = 0
        self.last_leak_time: float = time.time()
        self.contributing_events: List[Dict[str, Any]] = []

    def leak(self, current_time: float) -> None:
        """Removes one whole event for each elapsed leakspeed interval."""
        elapsed = current_time - self.last_leak_time
        if elapsed >= self.leakspeed_seconds:
            leaked_count = int(elapsed // self.leakspeed_seconds)
            self.current_drops = max(0, self.current_drops - leaked_count)
            self.last_leak_time = self.last_leak_time + (leaked_count * self.leakspeed_seconds)
            if self.current_drops == 0:
                self.contributing_events.clear()

    def pour(self, current_time: float, event_meta: Dict[str, Any]) -> Tuple[bool, int]:
        """
        Pours an event into the bucket.
        Returns:
            Tuple of (is_overflow: bool, current_event_count: int)
        """
        # If this is the very first drop into an empty bucket, anchor last_leak_time
        if self.current_drops == 0:
            self.last_leak_time = current_time
        else:
            self.leak(current_time)

        self.current_drops += 1
        self.contributing_events.append(event_meta)

        if self.current_drops >= self.capacity:
            return True, self.current_drops

        return False, self.current_drops


class TriggerBucket:
    """
    Trigger Bucket (capacity: 0).
    Any event poured into this bucket causes an immediate overflow.
    Used for signature-based and zero-tolerance exploit attempts (e.g. SQLi, Path Traversal).
    """

    def __init__(self, name: str, stack_key: str):
        self.name = name
        self.stack_key = stack_key
        self.capacity = 0
        self.leakspeed_seconds = 0.0
        self.contributing_events: List[Dict[str, Any]] = []

    def pour(self, current_time: float, event_meta: Dict[str, Any]) -> Tuple[bool, int]:
        self.contributing_events.append(event_meta)
        return True, 1


class UniqBucket:
    """
    Uniq Bucket.
    Enforces uniqueness: extracts a property (e.g. port or username) from each event.
    Only unique values within the time window contribute towards capacity.
    Used for port scan detection and credential stuffing across multiple accounts.
    """

    def __init__(self, name: str, stack_key: str, capacity: int, leakspeed_seconds: float):
        self.name = name
        self.stack_key = stack_key
        self.capacity = max(1, capacity)
        self.leakspeed_seconds = max(1.0, leakspeed_seconds)
        self.seen_values: Dict[str, float] = {}  # value -> last_seen_timestamp
        self.contributing_events: List[Dict[str, Any]] = []

    def purge_expired(self, current_time: float) -> None:
        expired = [val for val, ts in self.seen_values.items() if (current_time - ts) > self.leakspeed_seconds]
        for val in expired:
            del self.seen_values[val]

    def pour(self, current_time: float, event_meta: Dict[str, Any], uniq_val: Optional[str] = None) -> Tuple[bool, int]:
        self.purge_expired(current_time)
        if uniq_val is not None:
            self.seen_values[str(uniq_val)] = current_time

        self.contributing_events.append(event_meta)
        unique_count = len(self.seen_values)

        if unique_count >= self.capacity:
            return True, unique_count

        return False, unique_count

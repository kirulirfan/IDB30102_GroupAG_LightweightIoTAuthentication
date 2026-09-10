"""
nonce_store.py

Tracks nonces that have already been used per device, so the gateway can
reject replayed authentication requests and replayed sensor messages
(Table 3.3 STRIDE control: "Reject replayed messages").

A simple in-memory store is sufficient for the proposal-stage prototype;
a production system would use a persistent store with TTL-based eviction.
"""

import time


class NonceStore:
    def __init__(self, ttl_seconds: float = 300.0):
        self.ttl_seconds = ttl_seconds
        # device_id -> {nonce_bytes: first_seen_timestamp}
        self._seen = {}

    def _prune(self, device_id: str):
        now = time.time()
        bucket = self._seen.get(device_id, {})
        expired = [n for n, ts in bucket.items() if now - ts > self.ttl_seconds]
        for n in expired:
            del bucket[n]

    def seen(self, device_id: str, nonce: bytes) -> bool:
        """Return True if this nonce has already been used by this device."""
        self._prune(device_id)
        return nonce in self._seen.get(device_id, {})

    def record(self, device_id: str, nonce: bytes):
        """Mark a nonce as used for this device."""
        self._seen.setdefault(device_id, {})[nonce] = time.time()

    def clear(self):
        self._seen.clear()

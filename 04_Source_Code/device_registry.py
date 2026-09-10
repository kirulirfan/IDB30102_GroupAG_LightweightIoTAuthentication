"""
device_registry.py

Simulated device registry for the lightweight IoT mutual-authentication
framework (Chapter 3, Section 3.7.1 Registration stage).

IMPORTANT - DEMONSTRATION USE ONLY:
Device "secrets" here are randomly generated locally, purely for this
local simulation. They are NOT real credentials and hold no value outside
this demo. Do NOT reuse this registry design for production systems, and
NEVER commit real secrets, passwords or API keys to a public GitHub
repository (see Section 3.11 Ethical and Legal Considerations).
"""

import secrets
import time


class DeviceRegistry:
    """In-memory registry of simulated IoT devices and their shared secrets."""

    def __init__(self):
        # device_id -> {"secret": bytes, "status": "active" | "revoked", "registered_at": float}
        self._devices = {}

    def register_device(self, device_id: str, secret: bytes = None) -> bytes:
        """Register a new device. Generates a random 32-byte secret if none supplied."""
        if secret is None:
            secret = secrets.token_bytes(32)
        self._devices[device_id] = {
            "secret": secret,
            "status": "active",
            "registered_at": time.time(),
        }
        return secret

    def revoke_device(self, device_id: str):
        """Mark a device as revoked; it will fail all future authentication attempts."""
        if device_id in self._devices:
            self._devices[device_id]["status"] = "revoked"

    def is_registered(self, device_id: str) -> bool:
        """True only if the device exists AND is currently active (not revoked)."""
        record = self._devices.get(device_id)
        return record is not None and record["status"] == "active"

    def get_secret(self, device_id: str) -> bytes:
        """Return the shared secret for an active device, or raise KeyError."""
        record = self._devices.get(device_id)
        if record is None or record["status"] != "active":
            raise KeyError(f"Device '{device_id}' is not an active registered device.")
        return record["secret"]

    def list_devices(self) -> dict:
        """Return a status-only view of the registry (never exposes secrets)."""
        return {
            device_id: {"status": rec["status"]}
            for device_id, rec in self._devices.items()
        }


if __name__ == "__main__":
    # Small standalone demo so this file can be run directly:
    #   python device_registry.py
    print("=== Device Registry Demo ===")
    registry = DeviceRegistry()

    for i in range(1, 4):
        device_id = f"device-{i:03d}"
        registry.register_device(device_id)
        print(f"Registered {device_id}: {registry.list_devices()[device_id]}")

    print("\nRevoking device-002 ...")
    registry.revoke_device("device-002")

    print("\nRegistry status:")
    for device_id, info in registry.list_devices().items():
        print(f"  {device_id}: {info['status']}")

    print("\nis_registered('device-001') ->", registry.is_registered("device-001"))
    print("is_registered('device-002') ->", registry.is_registered("device-002"), "(revoked)")
    print("is_registered('device-999') ->", registry.is_registered("device-999"), "(never registered)")

"""
encryption_demo.py

Standalone demonstration of the proposed session-key derivation and
authenticated-encryption stage (Chapter 3, Sections 3.7.3 and 3.7.4).

After a device and gateway complete mutual authentication (see
authentication_demo.py), both sides hold the same temporary session key.
This script shows that session key being used to encrypt and authenticate
a sensor-data message with AES-256-GCM, and demonstrates that the gateway
correctly detects a tampered ciphertext or a tampered authentication tag.

Run:
    python encryption_demo.py
"""

import json
import time

from device_registry import DeviceRegistry
from event_logger import EventLog
from protocol import IoTDevice, IoTGateway, run_full_handshake


def print_message_summary(label, message):
    print(f"[{label}] device_id={message['device_id']}  "
          f"nonce={message['msg_nonce'].hex()[:8]}...  "
          f"iv={message['iv'].hex()}  "
          f"ciphertext_len={len(message['ciphertext'])} bytes")


def demo_normal_secure_message():
    print("=" * 70)
    print("SCENARIO 1: Authenticated device sends an encrypted sensor reading")
    print("=" * 70)

    registry = DeviceRegistry()
    secret = registry.register_device("device-001")
    log = EventLog()
    gateway = IoTGateway(registry, event_log=log)
    device = IoTDevice("device-001", secret)

    auth_result, mutually_verified = run_full_handshake(device, gateway)
    assert auth_result.accepted and mutually_verified
    session_key = auth_result.session_key
    print("[Setup  ] Mutual authentication completed; session key established.\n")

    sensor_reading = {
        "temperature": 27.4,
        "humidity": 61.2,
        "device_status": "normal",
        "motion_status": "no_motion",
    }
    print(f"[Device ] Plaintext sensor reading: {sensor_reading}")

    message = device.encrypt_message(session_key, sensor_reading)
    print_message_summary("Device ", message)

    result = gateway.receive_message(message, session_key)
    print(f"[Gateway] Decryption/verification result: accepted={result.accepted} ({result.reason})")
    if result.accepted:
        recovered = json.loads(result.plaintext.decode())
        print(f"[Gateway] Recovered plaintext           : {recovered}")
        print(f"[Check  ] Recovered == original          : {recovered == sensor_reading}")
        print("\n>>> RESULT: Message accepted, decrypted and forwarded to the application server.")

    print("\nSecurity event log:")
    log.print_recent()


def demo_tampered_ciphertext_detected():
    print("\n" + "=" * 70)
    print("SCENARIO 2: Attacker modifies the ciphertext in transit")
    print("=" * 70)

    registry = DeviceRegistry()
    secret = registry.register_device("device-001")
    log = EventLog()
    gateway = IoTGateway(registry, event_log=log)
    device = IoTDevice("device-001", secret)

    auth_result, _ = run_full_handshake(device, gateway)
    session_key = auth_result.session_key

    message = device.encrypt_message(session_key, {"temperature": 30.0, "humidity": 55.0})
    print_message_summary("Device ", message)

    # Simulate an on-path attacker flipping one bit of the ciphertext.
    tampered = dict(message)
    corrupted = bytearray(tampered["ciphertext"])
    corrupted[0] ^= 0xFF
    tampered["ciphertext"] = bytes(corrupted)
    print("[Attacker] Flipped one byte of the ciphertext before forwarding it to the gateway.")

    result = gateway.receive_message(tampered, session_key)
    print(f"[Gateway ] Decryption/verification result: accepted={result.accepted} ({result.reason})")
    print(f">>> RESULT: {'Tampering correctly DETECTED and message REJECTED.' if not result.accepted else 'UNEXPECTED ACCEPT - bug!'}")

    print("\nSecurity event log:")
    log.print_recent()


def demo_replayed_message_detected():
    print("\n" + "=" * 70)
    print("SCENARIO 3: Attacker replays a previously captured, valid message")
    print("=" * 70)

    registry = DeviceRegistry()
    secret = registry.register_device("device-001")
    log = EventLog()
    gateway = IoTGateway(registry, event_log=log)
    device = IoTDevice("device-001", secret)

    auth_result, _ = run_full_handshake(device, gateway)
    session_key = auth_result.session_key

    message = device.encrypt_message(session_key, {"temperature": 26.0, "humidity": 58.0})

    first = gateway.receive_message(message, session_key)
    print(f"[Gateway] First delivery  : accepted={first.accepted} ({first.reason})")

    print("[Attacker] Captures the exact same message and resends it unmodified.")
    replay = gateway.receive_message(message, session_key)
    print(f"[Gateway] Replayed delivery: accepted={replay.accepted} ({replay.reason})")
    print(f">>> RESULT: {'Replay correctly DETECTED and REJECTED.' if not replay.accepted else 'UNEXPECTED ACCEPT - bug!'}")

    print("\nSecurity event log:")
    log.print_recent()


if __name__ == "__main__":
    demo_normal_secure_message()
    demo_tampered_ciphertext_detected()
    demo_replayed_message_detected()

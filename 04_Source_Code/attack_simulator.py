"""
attack_simulator.py

Runs the ten malicious test scenarios listed in Chapter 3, Section 3.8.3
("Malicious test data") against the live protocol implementation in
protocol.py, and reports PASS/FAIL for each (PASS = the attack was
correctly rejected/detected by the gateway).

This produces the evidence used for the "attack-detection rate" and
"functional-test pass rate" metrics in Table 3.5, and backs the
Demonstration phase (Section 3.2.4) and STRIDE controls (Table 3.3).

Run:
    python attack_simulator.py
"""

import time

from device_registry import DeviceRegistry
from event_logger import EventLog
from protocol import IoTDevice, IoTGateway, run_full_handshake


class ScenarioResult:
    def __init__(self, name, expected_rejected, actually_rejected, reason):
        self.name = name
        self.expected_rejected = expected_rejected
        self.actually_rejected = actually_rejected
        self.reason = reason

    @property
    def passed(self):
        return self.expected_rejected == self.actually_rejected

    def __str__(self):
        status = "PASS" if self.passed else "FAIL"
        outcome = "REJECTED" if self.actually_rejected else "ACCEPTED"
        return f"[{status}] {self.name:<45} -> {outcome:<9} ({self.reason})"


def scenario_unknown_device():
    registry = DeviceRegistry()
    gateway = IoTGateway(registry, event_log=EventLog())
    attacker = IoTDevice("attacker-device-999", b"\x11" * 32)
    nonce_d = attacker.initiate_authentication()
    nonce_g = gateway.start_authentication(attacker.device_id, nonce_d)
    rejected = nonce_g is None
    return ScenarioResult("1. Unknown device identifier", True, rejected,
                           "no challenge issued" if rejected else "challenge issued")


def scenario_wrong_secret():
    registry = DeviceRegistry()
    registry.register_device("device-002")
    gateway = IoTGateway(registry, event_log=EventLog())
    impostor = IoTDevice("device-002", b"\x00" * 32)
    nonce_d = impostor.initiate_authentication()
    nonce_g = gateway.start_authentication(impostor.device_id, nonce_d)
    response = impostor.compute_response(nonce_d, nonce_g)
    result = gateway.verify_response(impostor.device_id, response)
    return ScenarioResult("2. Registered ID with incorrect secret", True,
                           not result.accepted, result.reason)


def scenario_replayed_auth_request():
    registry = DeviceRegistry()
    secret = registry.register_device("device-003")
    gateway = IoTGateway(registry, event_log=EventLog())
    device = IoTDevice("device-003", secret)

    nonce_d = device.initiate_authentication()
    nonce_g = gateway.start_authentication(device.device_id, nonce_d)
    response = device.compute_response(nonce_d, nonce_g)
    first = gateway.verify_response(device.device_id, response)
    assert first.accepted

    # Attacker replays the exact same (nonce_d, response) pair again.
    nonce_g2 = gateway.start_authentication(device.device_id, nonce_d)  # gateway re-issues challenge
    replay_result = gateway.verify_response(device.device_id, response)
    return ScenarioResult("3. Replayed authentication request", True,
                           not replay_result.accepted, replay_result.reason)


def scenario_replayed_sensor_message():
    registry = DeviceRegistry()
    secret = registry.register_device("device-004")
    gateway = IoTGateway(registry, event_log=EventLog())
    device = IoTDevice("device-004", secret)
    auth_result, _ = run_full_handshake(device, gateway)
    message = device.encrypt_message(auth_result.session_key, {"temperature": 25.0})

    first = gateway.receive_message(message, auth_result.session_key)
    assert first.accepted
    replay = gateway.receive_message(message, auth_result.session_key)
    return ScenarioResult("4. Replayed encrypted sensor message", True,
                           not replay.accepted, replay.reason)


def scenario_modified_ciphertext():
    registry = DeviceRegistry()
    secret = registry.register_device("device-005")
    gateway = IoTGateway(registry, event_log=EventLog())
    device = IoTDevice("device-005", secret)
    auth_result, _ = run_full_handshake(device, gateway)
    message = device.encrypt_message(auth_result.session_key, {"temperature": 25.0})

    tampered = dict(message)
    corrupted = bytearray(tampered["ciphertext"])
    corrupted[-1] ^= 0xFF
    tampered["ciphertext"] = bytes(corrupted)

    result = gateway.receive_message(tampered, auth_result.session_key)
    return ScenarioResult("5. Modified ciphertext", True, not result.accepted, result.reason)


def scenario_modified_tag():
    # AES-GCM bundles the tag with the ciphertext; corrupting the final
    # 16 bytes corrupts the authentication tag specifically.
    registry = DeviceRegistry()
    secret = registry.register_device("device-006")
    gateway = IoTGateway(registry, event_log=EventLog())
    device = IoTDevice("device-006", secret)
    auth_result, _ = run_full_handshake(device, gateway)
    message = device.encrypt_message(auth_result.session_key, {"temperature": 25.0})

    tampered = dict(message)
    corrupted = bytearray(tampered["ciphertext"])
    corrupted[-1] ^= 0x01  # flip a bit inside the 16-byte GCM tag suffix
    tampered["ciphertext"] = bytes(corrupted)

    result = gateway.receive_message(tampered, auth_result.session_key)
    return ScenarioResult("6. Modified authentication tag", True, not result.accepted, result.reason)


def scenario_expired_timestamp():
    registry = DeviceRegistry()
    secret = registry.register_device("device-007")
    gateway = IoTGateway(registry, event_log=EventLog(), max_clock_skew=5.0)
    device = IoTDevice("device-007", secret)
    auth_result, _ = run_full_handshake(device, gateway)

    old_timestamp = time.time() - 3600  # one hour old
    message = device.encrypt_message(auth_result.session_key, {"temperature": 25.0},
                                      timestamp=old_timestamp)
    result = gateway.receive_message(message, auth_result.session_key)
    return ScenarioResult("7. Expired timestamp", True, not result.accepted, result.reason)


def scenario_reused_nonce():
    registry = DeviceRegistry()
    secret = registry.register_device("device-008")
    gateway = IoTGateway(registry, event_log=EventLog())
    device = IoTDevice("device-008", secret)
    auth_result, _ = run_full_handshake(device, gateway)

    fixed_nonce = b"\x42" * 12
    msg1 = device.encrypt_message(auth_result.session_key, {"temperature": 25.0}, msg_nonce=fixed_nonce)
    r1 = gateway.receive_message(msg1, auth_result.session_key)
    assert r1.accepted

    # Same nonce reused for a different payload -> must be rejected as replay.
    msg2 = device.encrypt_message(auth_result.session_key, {"temperature": 99.9}, msg_nonce=fixed_nonce)
    r2 = gateway.receive_message(msg2, auth_result.session_key)
    return ScenarioResult("8. Reused nonce", True, not r2.accepted, r2.reason)


def scenario_revoked_device():
    registry = DeviceRegistry()
    secret = registry.register_device("device-009")
    gateway = IoTGateway(registry, event_log=EventLog())
    device = IoTDevice("device-009", secret)

    registry.revoke_device("device-009")  # revoke AFTER secret was issued, BEFORE auth attempt
    nonce_d = device.initiate_authentication()
    nonce_g = gateway.start_authentication(device.device_id, nonce_d)
    rejected = nonce_g is None
    return ScenarioResult("9. Revoked device identifier", True, rejected,
                           "no challenge issued" if rejected else "challenge issued")


def scenario_repeated_invalid_requests():
    registry = DeviceRegistry()
    gateway = IoTGateway(registry, event_log=EventLog())
    attacker = IoTDevice("attacker-flood", b"\x22" * 32)

    all_rejected = True
    for _ in range(20):
        nonce_d = attacker.initiate_authentication()
        nonce_g = gateway.start_authentication(attacker.device_id, nonce_d)
        if nonce_g is not None:
            all_rejected = False
    return ScenarioResult("10. Repeated invalid requests (local flood)", True,
                           all_rejected, "all 20 requests rejected" if all_rejected else "some accepted")


ALL_SCENARIOS = [
    scenario_unknown_device,
    scenario_wrong_secret,
    scenario_replayed_auth_request,
    scenario_replayed_sensor_message,
    scenario_modified_ciphertext,
    scenario_modified_tag,
    scenario_expired_timestamp,
    scenario_reused_nonce,
    scenario_revoked_device,
    scenario_repeated_invalid_requests,
]


def run_all(verbose: bool = True):
    results = [scenario() for scenario in ALL_SCENARIOS]
    if verbose:
        print("=" * 78)
        print("ATTACK SIMULATOR - Malicious Test Scenarios (Section 3.8.3)")
        print("=" * 78)
        for r in results:
            print(r)
        passed = sum(1 for r in results if r.passed)
        print("-" * 78)
        print(f"Result: {passed}/{len(results)} scenarios PASSED "
              f"(attack correctly detected and rejected).")
        print(f"Attack-detection rate: {passed / len(results) * 100:.1f}%")
    return results


if __name__ == "__main__":
    run_all()

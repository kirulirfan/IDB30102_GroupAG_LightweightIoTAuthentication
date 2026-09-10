"""
authentication_demo.py

Standalone demonstration of the proposed nonce-based challenge-response
mutual authentication protocol (Chapter 3, Section 3.7.2 Mutual
authentication stage). Prints each protocol step so the flow described in
Figure 3.2 can be seen directly in the terminal.

Run:
    python authentication_demo.py
"""

from device_registry import DeviceRegistry
from event_logger import EventLog
from protocol import IoTDevice, IoTGateway


def hexshort(b: bytes, n: int = 8) -> str:
    return b.hex()[:n] + "..."


def demo_successful_authentication():
    print("=" * 70)
    print("SCENARIO 1: Legitimate registered device - successful mutual authentication")
    print("=" * 70)

    registry = DeviceRegistry()
    secret = registry.register_device("device-001")
    log = EventLog()
    gateway = IoTGateway(registry, event_log=log)
    device = IoTDevice("device-001", secret)

    print(f"[Device ] Registered as 'device-001' with a 32-byte shared secret.")

    nonce_d = device.initiate_authentication()
    print(f"[Device ] -> Gateway : device_id='device-001', nonce_d={hexshort(nonce_d)}")

    nonce_g = gateway.start_authentication(device.device_id, nonce_d)
    print(f"[Gateway] Device is registered. Issuing challenge nonce_g={hexshort(nonce_g)}")
    print(f"[Gateway] -> Device  : nonce_g={hexshort(nonce_g)}")

    response = device.compute_response(nonce_d, nonce_g)
    print(f"[Device ] Computed HMAC response={hexshort(response)}")
    print(f"[Device ] -> Gateway : response={hexshort(response)}")

    result = gateway.verify_response(device.device_id, response)
    print(f"[Gateway] Verification result: accepted={result.accepted} ({result.reason})")

    if result.accepted:
        print(f"[Gateway] -> Device  : confirmation={hexshort(result.confirm)}")
        ok = device.verify_gateway_confirmation(result.confirm, nonce_g, nonce_d)
        print(f"[Device ] Gateway confirmation verified: {ok}")
        session_key = device.derive_session_key(nonce_d, nonce_g)
        gw_session_key = result.session_key
        print(f"[Device ] Derived session key: {hexshort(session_key)}")
        print(f"[Gateway] Derived session key: {hexshort(gw_session_key)}")
        print(f"[Check  ] Both session keys match: {session_key == gw_session_key}")
        print(f"\n>>> RESULT: Mutual authentication SUCCESSFUL. "
              f"Device and gateway now share a temporary session key.")
    else:
        print(f"\n>>> RESULT: Mutual authentication FAILED.")

    print("\nSecurity event log:")
    log.print_recent()


def demo_wrong_secret_rejected():
    print("\n" + "=" * 70)
    print("SCENARIO 2: Registered device ID used with an INCORRECT secret")
    print("=" * 70)

    registry = DeviceRegistry()
    registry.register_device("device-002")  # correct secret stored in registry
    wrong_secret = b"\x00" * 32              # attacker/misconfigured device guesses wrong secret
    log = EventLog()
    gateway = IoTGateway(registry, event_log=log)
    impostor_device = IoTDevice("device-002", wrong_secret)

    nonce_d = impostor_device.initiate_authentication()
    nonce_g = gateway.start_authentication(impostor_device.device_id, nonce_d)
    response = impostor_device.compute_response(nonce_d, nonce_g)
    result = gateway.verify_response(impostor_device.device_id, response)

    print(f"[Gateway] Verification result: accepted={result.accepted} ({result.reason})")
    print(f">>> RESULT: {'REJECTED as expected.' if not result.accepted else 'UNEXPECTED ACCEPT - bug!'}")
    print("\nSecurity event log:")
    log.print_recent()


def demo_unknown_device_rejected():
    print("\n" + "=" * 70)
    print("SCENARIO 3: Unregistered ('unknown') device attempts to authenticate")
    print("=" * 70)

    registry = DeviceRegistry()  # empty registry - no devices registered
    log = EventLog()
    gateway = IoTGateway(registry, event_log=log)
    unknown_device = IoTDevice("attacker-device-999", b"\x11" * 32)

    nonce_d = unknown_device.initiate_authentication()
    nonce_g = gateway.start_authentication(unknown_device.device_id, nonce_d)

    print(f"[Gateway] Challenge issued (nonce_g): {nonce_g}")
    print(f">>> RESULT: {'REJECTED as expected (no challenge issued).' if nonce_g is None else 'UNEXPECTED ACCEPT - bug!'}")
    print("\nSecurity event log:")
    log.print_recent()


if __name__ == "__main__":
    demo_successful_authentication()
    demo_wrong_secret_rejected()
    demo_unknown_device_rejected()

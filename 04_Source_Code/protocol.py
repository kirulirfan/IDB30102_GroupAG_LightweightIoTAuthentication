"""
protocol.py

Core implementation of the proposed lightweight mutual-authentication and
encryption protocol described in Chapter 3, Section 3.7:

    3.7.1 Registration stage        -> DeviceRegistry (see device_registry.py)
    3.7.2 Mutual authentication     -> IoTGateway.start_authentication /
                                        IoTGateway.verify_response /
                                        IoTDevice.verify_gateway_confirmation
    3.7.3 Session-key stage         -> crypto_utils.derive_session_key
    3.7.4 Secure data stage         -> IoTDevice.encrypt_message /
                                        IoTGateway.receive_message

This module is imported by authentication_demo.py, encryption_demo.py,
attack_simulator.py and evaluation.py so that all four scripts exercise the
exact same protocol logic (no duplicated / diverging implementations).
"""

import time
import json

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    hmac_digest,
    constant_time_compare,
    new_nonce,
    derive_session_key,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
)
from nonce_store import NonceStore
from event_logger import EventLog
from device_registry import DeviceRegistry


MAX_CLOCK_SKEW_SECONDS = 5.0


class AuthResult:
    """Small result object returned by IoTGateway.verify_response()."""
    def __init__(self, accepted: bool, reason: str,
                 confirm: bytes = None, session_key: bytes = None):
        self.accepted = accepted
        self.reason = reason
        self.confirm = confirm
        self.session_key = session_key


class MessageResult:
    """Small result object returned by IoTGateway.receive_message()."""
    def __init__(self, accepted: bool, reason: str, plaintext: bytes = None):
        self.accepted = accepted
        self.reason = reason
        self.plaintext = plaintext


class IoTDevice:
    """Simulated resource-constrained IoT device (Section 3.6, IoT Device box)."""

    def __init__(self, device_id: str, secret: bytes):
        self.device_id = device_id
        self.secret = secret

    def initiate_authentication(self) -> bytes:
        """Step 1: device generates a fresh nonce to start authentication."""
        return new_nonce()

    def compute_response(self, nonce_d: bytes, nonce_g: bytes) -> bytes:
        """Step 3: device answers the gateway's challenge nonce."""
        message = self.device_id.encode() + b"|" + nonce_d + b"|" + nonce_g
        return hmac_digest(self.secret, message)

    def verify_gateway_confirmation(self, confirm: bytes, nonce_g: bytes, nonce_d: bytes) -> bool:
        """Step 5: device verifies the gateway is genuine (mutual authentication)."""
        expected = hmac_digest(self.secret, nonce_g + b"|" + nonce_d)
        return constant_time_compare(expected, confirm)

    def derive_session_key(self, nonce_d: bytes, nonce_g: bytes) -> bytes:
        return derive_session_key(self.secret, nonce_d, nonce_g)

    def encrypt_message(self, session_key: bytes, payload: dict,
                         msg_nonce: bytes = None, timestamp: float = None):
        """
        Encrypt a sensor-data payload (dict) under the session key.
        Returns a dict representing the wire message, matching Section 3.7.4:
        device identifier, message nonce, timestamp, ciphertext, tag (bundled
        by AES-GCM into the ciphertext itself).
        """
        msg_nonce = msg_nonce or new_nonce(12)
        timestamp = timestamp if timestamp is not None else time.time()
        plaintext = json.dumps(payload).encode()
        associated_data = self.device_id.encode() + b"|" + msg_nonce + b"|" + str(timestamp).encode()
        iv, ciphertext = aes_gcm_encrypt(session_key, plaintext, associated_data)
        return {
            "device_id": self.device_id,
            "msg_nonce": msg_nonce,
            "timestamp": timestamp,
            "iv": iv,
            "ciphertext": ciphertext,
        }


class IoTGateway:
    """Simulated IoT gateway (Section 3.6, IoT Gateway box)."""

    def __init__(self, registry: DeviceRegistry, event_log: EventLog = None,
                 nonce_ttl_seconds: float = 300.0,
                 max_clock_skew: float = MAX_CLOCK_SKEW_SECONDS):
        self.registry = registry
        self.log = event_log or EventLog()
        self.nonce_store = NonceStore(ttl_seconds=nonce_ttl_seconds)
        self.max_clock_skew = max_clock_skew
        self._pending_challenges = {}  # device_id -> {"nonce_d", "nonce_g", "issued_at"}

    # ---- Step 2: registration check + challenge issuance -------------------
    def start_authentication(self, device_id: str, nonce_d: bytes):
        """Gateway receives (device_id, nonce_d) and, if registered, issues a challenge."""
        if not self.registry.is_registered(device_id):
            self.log.record(device_id, "AUTH_REJECTED", "device not registered or revoked")
            return None
        nonce_g = new_nonce()
        self._pending_challenges[device_id] = {
            "nonce_d": nonce_d, "nonce_g": nonce_g, "issued_at": time.time(),
        }
        return nonce_g

    # ---- Step 4: verify device response, derive session key ----------------
    def verify_response(self, device_id: str, response: bytes) -> AuthResult:
        pending = self._pending_challenges.get(device_id)
        if pending is None:
            self.log.record(device_id, "AUTH_REJECTED", "no pending challenge (unsolicited response)")
            return AuthResult(False, "no_pending_challenge")

        try:
            secret = self.registry.get_secret(device_id)
        except KeyError:
            self.log.record(device_id, "AUTH_REJECTED", "device not active at verification time")
            return AuthResult(False, "device_not_active")

        nonce_d, nonce_g = pending["nonce_d"], pending["nonce_g"]

        # Replay protection on the authentication nonce itself.
        if self.nonce_store.seen(device_id, nonce_d):
            self.log.record(device_id, "AUTH_REJECTED", "replayed authentication nonce")
            return AuthResult(False, "replayed_auth_nonce")

        expected = hmac_digest(secret, device_id.encode() + b"|" + nonce_d + b"|" + nonce_g)
        if not constant_time_compare(expected, response):
            self.log.record(device_id, "AUTH_REJECTED", "invalid authentication response")
            return AuthResult(False, "invalid_response")

        # Accept: mark nonce used, build confirmation + session key.
        self.nonce_store.record(device_id, nonce_d)
        confirm = hmac_digest(secret, nonce_g + b"|" + nonce_d)
        session_key = derive_session_key(secret, nonce_d, nonce_g)
        self.log.record(device_id, "AUTH_ACCEPTED", "mutual authentication successful")
        del self._pending_challenges[device_id]
        return AuthResult(True, "ok", confirm=confirm, session_key=session_key)

    # ---- Step 6: verify + decrypt a secure sensor message -------------------
    def receive_message(self, message: dict, session_key: bytes) -> MessageResult:
        device_id = message["device_id"]
        msg_nonce = message["msg_nonce"]
        timestamp = message["timestamp"]
        iv = message["iv"]
        ciphertext = message["ciphertext"]

        if not self.registry.is_registered(device_id):
            self.log.record(device_id, "MESSAGE_REJECTED", "device not registered or revoked")
            return MessageResult(False, "device_not_registered")

        if abs(time.time() - timestamp) > self.max_clock_skew:
            self.log.record(device_id, "MESSAGE_REJECTED", "timestamp outside freshness window")
            return MessageResult(False, "expired_timestamp")

        if self.nonce_store.seen(device_id, msg_nonce):
            self.log.record(device_id, "MESSAGE_REJECTED", "replayed message nonce")
            return MessageResult(False, "replayed_message")

        associated_data = device_id.encode() + b"|" + msg_nonce + b"|" + str(timestamp).encode()
        try:
            plaintext = aes_gcm_decrypt(session_key, iv, ciphertext, associated_data)
        except InvalidTag:
            self.log.record(device_id, "MESSAGE_REJECTED", "authentication tag invalid (tampering detected)")
            return MessageResult(False, "invalid_tag")

        self.nonce_store.record(device_id, msg_nonce)
        self.log.record(device_id, "MESSAGE_ACCEPTED", "message decrypted and verified")
        return MessageResult(True, "ok", plaintext=plaintext)


def run_full_handshake(device: IoTDevice, gateway: IoTGateway):
    """
    Convenience helper that runs one complete, legitimate registration ->
    mutual authentication -> session-key derivation handshake and returns
    (auth_result, mutually_verified: bool).
    """
    nonce_d = device.initiate_authentication()
    nonce_g = gateway.start_authentication(device.device_id, nonce_d)
    if nonce_g is None:
        return AuthResult(False, "device_not_registered"), False

    response = device.compute_response(nonce_d, nonce_g)
    result = gateway.verify_response(device.device_id, response)
    if not result.accepted:
        return result, False

    mutually_verified = device.verify_gateway_confirmation(result.confirm, nonce_g, nonce_d)
    return result, mutually_verified

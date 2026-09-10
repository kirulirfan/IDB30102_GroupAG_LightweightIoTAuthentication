"""
crypto_utils.py

Shared cryptographic helper functions for the lightweight IoT mutual-
authentication and encryption framework proposed in Chapter 3 of the
Research Proposal:

    - HMAC-SHA-256 for challenge-response authentication and session-key
      derivation.
    - AES-256-GCM for authenticated encryption of sensor messages
      (confidentiality + integrity in one primitive).

This is a PROPOSAL-STAGE / EDUCATIONAL prototype. It demonstrates the
protocol logic described in the proposal; it is not a hardened,
production-ready security library.

Dependencies: `cryptography` (pip install cryptography)
"""

import hmac
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag  # re-exported for callers

HASH_ALGO = hashlib.sha256
SESSION_KEY_SIZE = 32   # AES-256
NONCE_SIZE = 16         # bytes, protocol-level nonce (device/gateway)
AES_GCM_IV_SIZE = 12    # bytes, standard AES-GCM IV size


def hmac_digest(key: bytes, message: bytes) -> bytes:
    """Return the HMAC-SHA-256 digest of `message` under `key`."""
    return hmac.new(key, message, HASH_ALGO).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison of two byte strings."""
    return hmac.compare_digest(a, b)


def new_nonce(size: int = NONCE_SIZE) -> bytes:
    """Generate a fresh cryptographically random nonce."""
    return os.urandom(size)


def derive_session_key(secret: bytes, nonce_d: bytes, nonce_g: bytes) -> bytes:
    """
    Derive a temporary session key from the long-term shared secret and the
    two nonces exchanged during mutual authentication:

        session_key = HMAC(secret, "session" || nonce_d || nonce_g)

    The resulting key is scoped to this authentication session only and
    must not be reused across unrelated sessions.
    """
    return hmac_digest(secret, b"session|" + nonce_d + b"|" + nonce_g)[:SESSION_KEY_SIZE]


def aes_gcm_encrypt(session_key: bytes, plaintext: bytes, associated_data: bytes = b""):
    """
    Encrypt + authenticate `plaintext` under `session_key`.
    Returns (iv, ciphertext_with_tag).
    """
    aesgcm = AESGCM(session_key)
    iv = os.urandom(AES_GCM_IV_SIZE)
    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data)
    return iv, ciphertext


def aes_gcm_decrypt(session_key: bytes, iv: bytes, ciphertext: bytes,
                     associated_data: bytes = b"") -> bytes:
    """
    Decrypt + verify `ciphertext` under `session_key`.
    Raises cryptography.exceptions.InvalidTag if the message was tampered
    with, or if the wrong key/associated data is supplied.
    """
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(iv, ciphertext, associated_data)

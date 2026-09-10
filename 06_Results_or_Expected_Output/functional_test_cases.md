# Functional Test Cases

These test cases are executed by `04_Source_Code/attack_simulator.py` and the demo
scripts, and all currently PASS against the preliminary prototype.

| ID | Test Case | Steps | Expected Result | Actual Result |
|---|---|---|---|---|
| FT-01 | Legitimate device authenticates | Register device → run mutual-authentication handshake | Accepted, session key established | PASS |
| FT-02 | Legitimate device sends encrypted message | Complete FT-01 → encrypt sample payload → gateway receives | Accepted, plaintext recovered matches original | PASS |
| FT-03 | Unknown device rejected | Unregistered device attempts to start authentication | Rejected, no challenge issued | PASS |
| FT-04 | Wrong secret rejected | Registered device ID, incorrect secret, computes response | Rejected, invalid_response | PASS |
| FT-05 | Replayed authentication request rejected | Replay a previously used (nonce_d, response) pair | Rejected, replayed_auth_nonce | PASS |
| FT-06 | Replayed encrypted message rejected | Resend an already-accepted encrypted message unmodified | Rejected, replayed_message | PASS |
| FT-07 | Tampered ciphertext detected | Flip a bit in the ciphertext before delivery | Rejected, invalid_tag | PASS |
| FT-08 | Tampered authentication tag detected | Flip a bit in the GCM tag suffix before delivery | Rejected, invalid_tag | PASS |
| FT-09 | Expired timestamp rejected | Send a message timestamped 1 hour in the past | Rejected, expired_timestamp | PASS |
| FT-10 | Reused nonce rejected | Reuse the same message nonce for a second payload | Rejected, replayed_message | PASS |
| FT-11 | Revoked device rejected | Revoke a device, then attempt authentication | Rejected, no challenge issued | PASS |
| FT-12 | Repeated invalid requests all rejected | Send 20 authentication attempts from an unregistered device | All 20 rejected | PASS |

**Functional-test pass rate = 12/12 = 100%** for this preliminary prototype.

Run `python3 attack_simulator.py` (from `04_Source_Code/`) to reproduce FT-03 through
FT-12 directly, and `python3 encryption_demo.py` / `python3 authentication_demo.py` for
FT-01, FT-02, FT-07 and FT-08.

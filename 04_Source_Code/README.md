# 04_Source_Code

Preliminary Python prototype for the proposed **lightweight mutual-authentication and
encryption framework** described in Chapter 3 of the Research Proposal (Design Science
Research → Design and Development phase; Spiral Cycles 2–3).

This is a **proposal-stage prototype**, not a production system. Its purpose is to
demonstrate technical feasibility (per Assignment 2 requirements) and to generate the
evaluation evidence used in Table 3.5.

## Mapping to Research Proposal Section 3.10 (8 Security Scenarios)

The Research Proposal names 8 security scenarios; `attack_simulator.py` implements 10
(splitting "impersonation" and "replay" into two concrete sub-cases each, plus one
extra flood-style test) for more thorough coverage. Mapping:

| Proposal Scenario (Section 3.10) | Implemented As |
|---|---|
| Normal communication | `authentication_demo.py` / `encryption_demo.py` (not an attack_simulator scenario) |
| Impersonation attack | Scenarios 1 (unknown device) and 2 (wrong secret) |
| Replay attack | Scenarios 3 (replayed auth request) and 4 (replayed message) |
| Message tampering | Scenario 5 (modified ciphertext) |
| Modified authentication tag | Scenario 6 |
| Expired timestamp | Scenario 7 |
| Reused nonce | Scenario 8 |
| Revoked device identifier | Scenario 9 |
| *(extra, beyond the proposal)* | Scenario 10 (repeated invalid requests / local flood) |

## Files

| File | Purpose |
|---|---|
| `crypto_utils.py` | HMAC-SHA-256 and AES-256-GCM helper functions used by the protocol. |
| `nonce_store.py` | Tracks used nonces per device to detect/reject replay attacks. |
| `event_logger.py` | Timestamped security-event log (accepted/rejected requests, detected attacks). |
| `device_registry.py` | Simulated device registry (registration, revocation, secret lookup). Runnable standalone. |
| `protocol.py` | Core `IoTDevice` / `IoTGateway` classes implementing the full registration → mutual authentication → session-key → encrypted-message flow (Section 3.7). Imported by all demo scripts. |
| `authentication_demo.py` | Step-by-step demo of mutual authentication: success case, wrong-secret case, unknown-device case. Runnable standalone. |
| `encryption_demo.py` | Step-by-step demo of session-key encryption: normal message, tampered ciphertext (detected), replayed message (detected). Runnable standalone. |
| `attack_simulator.py` | Runs all **10** malicious test scenarios from Section 3.8.3 against the live protocol and reports PASS/FAIL. Runnable standalone. |
| `evaluation.py` | Runs the Table 3.5 evaluation (5/10/25/50 simulated devices, 30 trials each) and writes `../06_Results_or_Expected_Output/evaluation_results.csv`. Runnable standalone. |
| `run_demo.py` | **Recommended entry point** — runs everything above in one pass with clear section headers, for use in the GitHub Commit Demo video. |
| `requirements.txt` | Python dependencies (`cryptography`). |

## Installation and Execution

```bash
cd 04_Source_Code
python3 -m venv venv                # optional but recommended
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run everything in one pass (recommended for the demo video):
python3 run_demo.py

# Or run each stage individually:
python3 device_registry.py
python3 authentication_demo.py
python3 encryption_demo.py
python3 attack_simulator.py
python3 evaluation.py
```

All scripts print their results directly to the terminal. `evaluation.py` additionally
writes a CSV of results to `06_Results_or_Expected_Output/evaluation_results.csv`.

## Security Notice

This code is for local simulation and coursework demonstration only:

- Device "secrets" are generated locally at runtime with `secrets.token_bytes()`. They
  are **not** real credentials and are never written to disk or committed to GitHub.
- Do **not** copy this design into a production system without an independent security
  review — the crypto primitives are used correctly, but the protocol has not been
  formally verified (Section 3.9 / Table 3.3 STRIDE analysis is deliberately scoped
  to this prototype only).
- No real devices, live networks or third-party systems are contacted by this code. It
  is a fully local, in-memory simulation (Section 3.11 Ethical and Legal Considerations).

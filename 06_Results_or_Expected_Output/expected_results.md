# Expected / Preliminary Results

These results were produced by actually running the preliminary prototype in
`04_Source_Code/` (`python3 run_demo.py`), not fabricated. They are **proposal-stage**
results from a small local simulation (Section 3.10.5) and are expected to be extended
with larger-scale, longer-running tests during the main project.

## Table 3.5 Evaluation Metrics (see `evaluation_results.csv`)

| Devices | Auth Success % | FAR % | FRR % | Auth Latency (ms) | Encrypt (ms) | Decrypt (ms) | Overhead (bytes) | Peak Memory (bytes) |
|---|---|---|---|---|---|---|---|---|
| 5  | 100.0 | 0.0 | 0.0 | 0.014 | 0.008 | 0.006 | 40 | 3,472 |
| 10 | 100.0 | 0.0 | 0.0 | 0.014 | 0.008 | 0.008 | 40 | 3,408 |
| 25 | 100.0 | 0.0 | 0.0 | 0.014 | 0.008 | 0.005 | 40 | 3,343 |
| 50 | 100.0 | 0.0 | 0.0 | 0.014 | 0.009 | 0.006 | 40 | 3,248 |

**Interpretation:** authentication success rate stays at 100% and the false
acceptance/rejection rate stays at 0% as the number of simulated devices grows from 5 to
50, indicating the protocol logic scales correctly across device counts in this local
simulation. Authentication latency, encryption and decryption times remain sub-millisecond
because the prototype runs in-process on a single machine — real network latency and
constrained-hardware CPU cost are **not** captured at this proposal stage and are
identified as future work (e.g., porting to ESP32/Raspberry Pi hardware).

## Attack-Detection Rate (see `malicious_requests.csv`)

*(See `../04_Source_Code/README.md` for how these 10 implemented scenarios map onto
the 8 scenarios named in Research Proposal Section 3.10.)*


All **10/10** malicious scenarios defined in Section 3.8.3 were correctly detected and
rejected by the gateway: **Attack-detection rate = 100%**, **Functional-test pass rate =
100%** for this preliminary prototype.

| # | Scenario | Result |
|---|---|---|
| 1 | Unknown device identifier | REJECTED (no challenge issued) |
| 2 | Registered ID with incorrect secret | REJECTED (invalid response) |
| 3 | Replayed authentication request | REJECTED (replayed auth nonce) |
| 4 | Replayed encrypted sensor message | REJECTED (replayed message) |
| 5 | Modified ciphertext | REJECTED (invalid tag) |
| 6 | Modified authentication tag | REJECTED (invalid tag) |
| 7 | Expired timestamp | REJECTED (expired timestamp) |
| 8 | Reused nonce | REJECTED (replayed message) |
| 9 | Revoked device identifier | REJECTED (no challenge issued) |
| 10 | Repeated invalid requests (local flood) | REJECTED (all 20 requests) |

## Success Conditions Check (Section 3.10.5)

| # | Success condition | Status |
|---|---|---|
| 1 | All valid registered-device requests accepted | ✅ Met (100%) |
| 2 | Unknown-device / incorrect-secret requests rejected | ✅ Met |
| 3 | Replayed requests/messages rejected | ✅ Met |
| 4 | Tampered messages rejected | ✅ Met |
| 5 | FAR = 0% in the controlled test set | ✅ Met |
| 6 | FRR = 0% (or explained) | ✅ Met |
| 7 | Confidentiality + integrity present vs baseline | ✅ Met (AES-256-GCM) |
| 8 | Overhead measured and reported transparently | ✅ Met (see table above) |
| 9 | System remains functional as device count increases | ✅ Met (5→50 devices) |
| 10 | Tests reproducible from code + sample data + instructions | ✅ Met (see `04_Source_Code/README.md`) |

See `sample_output.txt` for the full, unedited terminal output of `python3 run_demo.py`.

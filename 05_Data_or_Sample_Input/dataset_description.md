# Dataset Description

All files in this folder are **generated locally** by the group's own prototype code in
`04_Source_Code/` (see `evaluation.py` and the one-off generation commands recorded in the
group's commit history). No confidential, private, sensitive or third-party data is used, per
Section 3.11 (Ethical and Legal Considerations).

## sample_sensor_data.csv
Five example IoT sensor readings matching the schema used throughout the prototype
(`timestamp, device_id, temperature, humidity, device_status, motion_status`). Used as the
`payload` input to `IoTDevice.encrypt_message()` in the demo and evaluation scripts.

## valid_requests.csv
Genuine output from running the full protocol (`protocol.run_full_handshake` +
`IoTGateway.receive_message`) for three legitimate, registered devices. Columns:
`device_id, request_type, accepted, latency_ms, reason`. Every row shows `accepted=True`,
demonstrating that legitimate registered devices are always authenticated and their
encrypted messages always accepted.

## malicious_requests.csv
Genuine output from `attack_simulator.py`, one row per malicious scenario defined in
Section 3.8.3 of the Research Proposal (unknown device, wrong secret, replayed
authentication request, replayed message, modified ciphertext, modified tag, expired
timestamp, reused nonce, revoked device, repeated invalid requests). All 10 scenarios show
`passed=True`, meaning the attack was correctly detected and rejected by the gateway.

## How to regenerate these files
```bash
cd ../04_Source_Code
python3 evaluation.py          # regenerates 06_Results_or_Expected_Output/evaluation_results.csv
python3 attack_simulator.py    # reproduces the malicious_requests.csv scenarios
```

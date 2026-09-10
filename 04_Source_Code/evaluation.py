"""
evaluation.py

Runs the proposal-stage evaluation described in Chapter 3, Section 3.10
(Proposed Evaluation Plan) and Table 3.5 (Proposed evaluation metrics):

  - Baseline: plaintext communication with NO authentication/encryption.
  - Proposed: full mutual-authentication + authenticated-encryption
    framework implemented in protocol.py.

It measures, over repeated trials and an increasing number of simulated
devices (5, 10, 25, 50 - Table 3.4):

  - Authentication success rate / FAR / FRR
  - Authentication latency
  - Encryption / decryption time
  - Communication overhead (bytes added vs. plaintext)
  - Approximate memory footprint of the security modules
  - Attack-detection rate (from attack_simulator.py)
  - Functional-test pass rate (from attack_simulator.py)

Results are printed as a table and written to
06_Results_or_Expected_Output/evaluation_results.csv so they can be
committed to GitHub as evidence (Table B.1 mapping: RO3).

IMPORTANT: these are proposal-stage, small-scale demonstration results
from a local simulation (see Section 3.10.5 - "these are proposal-stage
success conditions, not final experimental results").

Run:
    python evaluation.py
"""

import csv
import json
import os
import statistics
import sys
import time
import tracemalloc

from device_registry import DeviceRegistry
from event_logger import EventLog
from protocol import IoTDevice, IoTGateway, run_full_handshake
import attack_simulator

TRIALS_PER_DEVICE_COUNT = 30
DEVICE_COUNTS = [5, 10, 25, 50]
OUTPUT_CSV = os.path.join("..", "06_Results_or_Expected_Output", "evaluation_results.csv")


def baseline_send(payload: dict) -> bytes:
    """Baseline: plaintext JSON 'communication', no auth/encryption at all."""
    return json.dumps(payload).encode()


def measure_device_count(n_devices: int, trials: int = TRIALS_PER_DEVICE_COUNT):
    """Run baseline + proposed framework for n_devices devices, `trials` times each."""
    registry = DeviceRegistry()
    devices = []
    for i in range(n_devices):
        device_id = f"device-{i:04d}"
        secret = registry.register_device(device_id)
        devices.append(IoTDevice(device_id, secret))

    gateway = IoTGateway(registry, event_log=EventLog())

    sample_payload = {
        "temperature": 27.4, "humidity": 61.2,
        "device_status": "normal", "motion_status": "no_motion",
    }
    baseline_msg = baseline_send(sample_payload)
    baseline_size = len(baseline_msg)

    auth_latencies = []
    encrypt_times = []
    decrypt_times = []
    overheads = []
    auth_success = 0
    auth_total = 0
    far_count = 0       # unauthorised accepted (should stay 0)
    far_total = 0
    frr_count = 0        # legitimate rejected (should stay 0 ideally)
    frr_total = 0

    for trial in range(trials):
        device = devices[trial % n_devices]

        # --- Authentication latency (legitimate device) ---
        t0 = time.perf_counter()
        auth_result, mutually_verified = run_full_handshake(device, gateway)
        t1 = time.perf_counter()
        auth_latencies.append((t1 - t0) * 1000.0)  # ms
        auth_total += 1
        frr_total += 1
        if auth_result.accepted and mutually_verified:
            auth_success += 1
        else:
            frr_count += 1  # legitimate device wrongly rejected

        if not (auth_result.accepted and mutually_verified):
            continue

        session_key = auth_result.session_key

        # --- Encryption time ---
        t0 = time.perf_counter()
        message = device.encrypt_message(session_key, sample_payload)
        t1 = time.perf_counter()
        encrypt_times.append((t1 - t0) * 1000.0)

        # --- Decryption time ---
        t0 = time.perf_counter()
        result = gateway.receive_message(message, session_key)
        t1 = time.perf_counter()
        decrypt_times.append((t1 - t0) * 1000.0)

        # --- Communication overhead ---
        secured_size = len(message["iv"]) + len(message["ciphertext"]) + len(message["msg_nonce"])
        overheads.append(secured_size - baseline_size)

        # --- FAR: impostor with wrong secret against this device's ID ---
        impostor = IoTDevice(device.device_id, b"\xAA" * 32)
        nonce_d = impostor.initiate_authentication()
        nonce_g = gateway.start_authentication(impostor.device_id, nonce_d)
        far_total += 1
        if nonce_g is not None:
            response = impostor.compute_response(nonce_d, nonce_g)
            impostor_result = gateway.verify_response(impostor.device_id, response)
            if impostor_result.accepted:
                far_count += 1  # SECURITY FAILURE if this ever happens

    # --- Approximate memory footprint of the security modules (tracemalloc) ---
    tracemalloc.start()
    _registry = DeviceRegistry()
    _secret = _registry.register_device("mem-test-device")
    _gateway = IoTGateway(_registry, event_log=EventLog())
    _device = IoTDevice("mem-test-device", _secret)
    _auth_result, _ = run_full_handshake(_device, _gateway)
    _msg = _device.encrypt_message(_auth_result.session_key, sample_payload)
    _gateway.receive_message(_msg, _auth_result.session_key)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "n_devices": n_devices,
        "trials": trials,
        "auth_success_rate_pct": 100.0 * auth_success / auth_total if auth_total else 0.0,
        "far_pct": 100.0 * far_count / far_total if far_total else 0.0,
        "frr_pct": 100.0 * frr_count / frr_total if frr_total else 0.0,
        "avg_auth_latency_ms": statistics.mean(auth_latencies) if auth_latencies else 0.0,
        "avg_encrypt_time_ms": statistics.mean(encrypt_times) if encrypt_times else 0.0,
        "avg_decrypt_time_ms": statistics.mean(decrypt_times) if decrypt_times else 0.0,
        "avg_comm_overhead_bytes": statistics.mean(overheads) if overheads else 0.0,
        "peak_memory_bytes": peak,
    }


def print_table(rows):
    headers = ["Devices", "Auth OK %", "FAR %", "FRR %", "Auth (ms)",
               "Encrypt (ms)", "Decrypt (ms)", "Overhead (B)", "Peak Mem (B)"]
    col_widths = [max(len(h), 10) for h in headers]

    def fmt_row(vals):
        return " | ".join(str(v).ljust(w) for v, w in zip(vals, col_widths))

    print(fmt_row(headers))
    print("-+-".join("-" * w for w in col_widths))
    for r in rows:
        print(fmt_row([
            r["n_devices"],
            f"{r['auth_success_rate_pct']:.1f}",
            f"{r['far_pct']:.1f}",
            f"{r['frr_pct']:.1f}",
            f"{r['avg_auth_latency_ms']:.3f}",
            f"{r['avg_encrypt_time_ms']:.3f}",
            f"{r['avg_decrypt_time_ms']:.3f}",
            f"{r['avg_comm_overhead_bytes']:.1f}",
            r["peak_memory_bytes"],
        ]))


def write_csv(rows, path=OUTPUT_CSV):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main():
    print("=" * 90)
    print("EVALUATION - Proposed Framework vs Baseline (Section 3.10, Table 3.5)")
    print("=" * 90)

    rows = []
    for n in DEVICE_COUNTS:
        print(f"\nRunning {TRIALS_PER_DEVICE_COUNT} trials with {n} simulated device(s) ...")
        row = measure_device_count(n)
        rows.append(row)

    print("\n--- Summary Table (Table 3.5 metrics) ---")
    print_table(rows)

    write_csv(rows)
    print(f"\nResults written to: {os.path.abspath(OUTPUT_CSV)}")

    print("\n--- Attack-Detection Rate & Functional-Test Pass Rate (Section 3.10.3) ---")
    attack_results = attack_simulator.run_all(verbose=True)
    functional_pass_rate = 100.0 * sum(r.passed for r in attack_results) / len(attack_results)

    print("\n--- Overall Evaluation Summary ---")
    best = rows[-1]  # largest device count
    print(f"Authentication success rate  : {best['auth_success_rate_pct']:.1f}% (target: 100%)")
    print(f"False Acceptance Rate (FAR)  : {best['far_pct']:.1f}% (target: 0%)")
    print(f"False Rejection Rate (FRR)   : {best['frr_pct']:.1f}% (target: 0%)")
    print(f"Attack-detection rate        : {functional_pass_rate:.1f}%")
    print(f"Functional-test pass rate    : {functional_pass_rate:.1f}%")


if __name__ == "__main__":
    main()

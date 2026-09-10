"""
run_demo.py

Single entry point that runs the whole preliminary prototype end-to-end and
prints all output to the terminal, in this order:

    1. Device registry demo
    2. Authentication demo (legitimate device, wrong secret, unknown device)
    3. Encryption demo (normal message, tampered ciphertext, replayed message)
    4. Attack simulator (all 10 malicious scenarios from Section 3.8.3)
    5. Evaluation (Table 3.5 metrics across 5/10/25/50 simulated devices)

This is the recommended script to run for the GitHub Commit Demo video
(Section B, GitHub Commit Demo) as it shows the whole framework working in
a single pass.

Run:
    pip install -r requirements.txt
    python run_demo.py
"""

import device_registry
import authentication_demo
import encryption_demo
import attack_simulator
import evaluation


def section(title):
    print("\n\n" + "#" * 90)
    print("# " + title)
    print("#" * 90)


if __name__ == "__main__":
    section("PART 1 / 5 - DEVICE REGISTRY")
    device_registry.__dict__["__name__"]  # no-op, keeps linters quiet
    reg = device_registry.DeviceRegistry()
    for i in range(1, 4):
        did = f"device-{i:03d}"
        reg.register_device(did)
        print(f"Registered {did}: {reg.list_devices()[did]}")

    section("PART 2 / 5 - AUTHENTICATION DEMO")
    authentication_demo.demo_successful_authentication()
    authentication_demo.demo_wrong_secret_rejected()
    authentication_demo.demo_unknown_device_rejected()

    section("PART 3 / 5 - ENCRYPTION DEMO")
    encryption_demo.demo_normal_secure_message()
    encryption_demo.demo_tampered_ciphertext_detected()
    encryption_demo.demo_replayed_message_detected()

    section("PART 4 / 5 - ATTACK SIMULATOR (10 malicious scenarios)")
    attack_simulator.run_all()

    section("PART 5 / 5 - EVALUATION (Table 3.5 metrics)")
    evaluation.main()

    section("DONE - all demos completed successfully")

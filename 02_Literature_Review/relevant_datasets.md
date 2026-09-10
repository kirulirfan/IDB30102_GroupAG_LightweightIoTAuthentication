# Relevant Datasets Identified from Previous Studies

Drawn from Section 2.7.1 of the Research Proposal (Chapter 2).

| Theme | Type of Data Used in Prior Studies | Devices / Sources |
|---|---|---|
| PUF-based authentication | Challenge-response pairs (CRPs) | FPGA, Arduino, ESP32 |
| Blockchain-based authentication | Simulated blockchain ledgers / small IoT test environments | Simulated blockchain testbeds |
| Lightweight cryptography and mutual authentication | Network traffic, MQTT logs, gateway test logs | Simulated device-gateway communication |
| Machine-learning and physical-layer authentication | Device behaviour logs, PUF responses, RAM data, wireless-signal data | Small, controlled-environment datasets |

## Key Finding (Gap 2.8.2)
**There is no common public dataset** that can be used to fairly compare IoT
authentication methods across studies — each group of researchers built its own
dataset with different devices, software and testing environments.

## Datasets Used in This Proposal
Because no suitable standard/public dataset exists, this research generates its own
data directly from the proposed prototype (consistent with how the reviewed studies
also built their own test data):

- **Sample sensor data:** device ID, temperature, humidity, device status, timestamp
  (see Chapter 1, Section 1.7 Scope, and `../.. /05_Data_or_Sample_Input/` if present in
  the repository, or the equivalent sample-data files alongside the source code).
- **Security-event / test-result logs:** generated while running the normal,
  impersonation, replay and message-tampering test scenarios described in Chapter 3.

No confidential, private, sensitive or third-party data is used or uploaded, in line
with the ethical scope stated in Chapter 1, Section 1.7 ("The study will not... use
confidential, private, sensitive or restricted data").

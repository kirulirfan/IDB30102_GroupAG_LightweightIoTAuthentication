# Comparison of Existing Techniques

This file summarises Section 2.7 of the Research Proposal (Chapter 2) and must be read
together with `comparison_of_existing_techniques.csv` (Table 2.1).

## 2.7.1 Comparison of Methods and Datasets

- **PUF-based authentication** uses challenge-response pairs (CRPs) collected from
  devices such as FPGA, Arduino and ESP32. Different devices produce different
  responses, but most studies used only a small number of devices tested in controlled
  environments.
- **Blockchain-based authentication** uses blockchain and smart contracts to manage
  device identities, mostly tested with simulated blockchain systems and small IoT test
  environments rather than large real-world IoT networks.
- **Lightweight cryptography and mutual authentication** studies used key exchange,
  encryption and authentication tested with network traffic, MQTT logs and gateway
  tests, including replay, impersonation and man-in-the-middle attacks. Different
  studies used different datasets and testing methods, which makes their results hard
  to compare directly.
- **Machine-learning and physical-layer authentication** studies used device behaviour,
  PUF responses, RAM data and wireless signals, but generally with small datasets from
  controlled environments.
- Overall, there is **no common public dataset** for comparing IoT authentication
  methods, which is one of the research gaps this proposal addresses (see
  `research_gap_analysis.md`, Gap 2.8.2).

## 2.7.2 Comparison of Security and Performance

- **PUF** studies usually measured authentication time, reliability, uniqueness and
  error rate — showing fast, low-cost authentication but on small device samples.
- **Blockchain** studies usually measured transaction time, communication cost, storage
  and scalability — useful for trust/identity management but resource-heavy for small
  IoT devices.
- **Lightweight cryptography and mutual authentication** studies usually measured
  processing cost, communication cost, authentication time and resistance to replay,
  impersonation and man-in-the-middle attacks, but many were simulation-only.
- **Machine-learning** studies usually measured accuracy, precision, recall, F1-score
  and false-positive rate; high accuracy does not always mean fake devices are reliably
  detected.

**Conclusion (matches Chapter 2, Section 2.7.1):** it is difficult to compare methods
directly because each study used different devices, datasets and testing methods. For
small IoT devices, processing time, communication cost and energy use matter, so both
security and performance must be tested together — which is exactly what the proposed
framework's evaluation plan does (baseline vs. proposed, under normal and attack
scenarios; see Chapter 3 / this repository's `03_Architecture_and_Flowchart/` and the
project README).

**Why lightweight cryptography and mutual authentication was chosen:** as concluded in
Chapter 2, this theme is the most suitable for the proposed research because it
balances security with the limited resources of IoT devices (e.g. Sarvaiya & Satange,
2022; Yodthong & Munlin, 2023; Seifelnasr et al., 2024). PUF can add low-cost device
identification as a future enhancement (Kumar & Mondal, 2024; Manivannan et al., 2024);
blockchain (Mukhandi et al., 2022; Aanandaram & Deepalakshmi, 2024) and machine learning
provide useful features but need more resources than this proposal's scope allows.

*(Full citation-to-PDF mapping: see `paper_theme_citation_mapping.csv` in this folder.)*

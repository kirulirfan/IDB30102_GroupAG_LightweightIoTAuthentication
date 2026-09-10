# Research Gap Analysis

This matches Section 2.8 of the Research Proposal (Chapter 2) exactly, so the GitHub
evidence and the written proposal stay consistent.

Although many studies have been done on IoT device authentication, four main gaps
remain:

## 2.8.1 Lack of Real-World Testing
Many studies tested their methods using simulations, small hardware tests or controlled
environments. These are useful but may not show how a method performs in a real IoT
network with many devices. **This research responds by** building a controlled
prototype that tests the authentication and encryption process end-to-end (see
`../03_Architecture_and_Flowchart/` and the project's source code / demo).

## 2.8.2 Lack of Standard Datasets
Most studies created their own datasets using different devices, software and testing
environments, making cross-study comparison difficult. **This research responds by**
collecting data directly from the proposed prototype during normal communication and
security tests, recording authentication results and system performance as it runs.

## 2.8.3 Limited Testing Against Different Attacks
Many studies tested common attacks (replay, impersonation, man-in-the-middle), but
newer attacks are still under-tested. **This research responds by** focusing on attacks
suitable for the proposed prototype: impersonation, replay and message tampering,
recording whether the framework detects or stops each one.

## 2.8.4 Security and Resource Usage
Stronger security usually needs more processing power, memory and energy — a problem
for resource-constrained IoT devices. Prior lightweight-cryptography studies show a
good security/resource balance is possible, but many were simulation-only.
**This research responds by** measuring both security and performance — authentication
time, processing time and communication cost — compared against a basic system with no
authentication or encryption.

## 2.8.5 Gap Addressed by This Research
Based on the above, this research focuses on the **lack of practical testing that looks
at both security and performance together**. The proposed lightweight mutual
authentication and encryption framework will be:
- tested in a controlled environment,
- compared with a basic (unsecured) baseline system,
- tested against impersonation, replay and message-tampering attacks, and
- measured on both security outcomes and performance/resource cost.

This directly maps to the three Research Objectives:

| Gap | Addressed by | Research Objective |
|---|---|---|
| 2.8.1 Lack of real-world testing | Controlled Python prototype tested end-to-end | RO2, RO3 |
| 2.8.2 Lack of standard datasets | Data generated and logged from the prototype itself | RO2, RO3 |
| 2.8.3 Limited attack testing | Impersonation, replay, message-tampering test scenarios | RO3 |
| 2.8.4 Security vs. resource usage | Baseline-vs-proposed comparison on time/processing/communication cost | RO3 |

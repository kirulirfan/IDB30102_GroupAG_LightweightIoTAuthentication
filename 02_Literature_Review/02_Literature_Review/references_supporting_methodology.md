# References Supporting the Proposed Methodology

All citations below are copied exactly from the group's verified reference list at
`../04_References/04References.md` (44 references, real DOIs). This file only selects
the subset that specifically supports the **framework design and methodology choices**
made in Chapter 3; for the complete list, see `04_References/04References.md` directly.

## References Supporting the Chosen Framework Design
(Lightweight cryptography and mutual authentication — the core basis of the proposed
framework, Chapter 2 Section 2.4 / 19-study theme)

- Sarvaiya, S. B., & Satange, D. N. (2022). Security in IP-based IoT node and device
  authentication. In *2022 IEEE International Conference on Blockchain and Distributed
  Systems Security (ICBDS)* (pp. 1-5). IEEE.
- Yodthong, W., & Munlin, M. (2023). Lightweight authentication and communication
  protocol for IoT devices. In *2023 10th International Conference on Electrical and
  Electronics Engineering (ICEEE)* (pp. 159-163). IEEE.
- Nurkifli, E. H., & Hwang, T. (2022). A secure lightweight authentication scheme in
  IoT environment with perfect forward and backward secrecy. In *2022 International
  Workshop on Big Data and Information Security (IWBIS)*. IEEE.
- Seifelnasr, M., AlTawy, R., Youssef, A. M., & Ghadafi, E. (2024). Privacy-preserving
  mutual authentication protocol with forward secrecy for IoT-Edge-Cloud. *IEEE
  Internet of Things Journal, 11*(5), 8105-8117.
- Gong, B., Zheng, G., Waqas, M., Tu, S., & Chen, S. (2023). LCDMA: Lightweight
  cross-domain mutual identity authentication scheme for Internet of Things. *IEEE
  Internet of Things Journal, 10*(14), 12590-12602.

These directly inform the proposed protocol design: nonce-based challenge-response
authentication, HMAC verification, session-key establishment and authenticated
encryption (Chapter 1, Section 1.7 Scope; repository README, Section 5).

## References Supporting the Comparison / Rejected Alternatives

**PUF-based authentication** (considered, not adopted as primary mechanism):
Kumar, D., & Mondal, B. (2024); Manivannan, S., Chakraborty, R. S., Chakrabarti, I., &
Rangasamy, J. (2024); Petzi, L., Dmitrienko, A., & Visconti, I. (2024) — cited as
evidence of PUF's environmental sensitivity and small test samples (Chapter 2, Section
2.3).

**Blockchain-based authentication** (considered, not adopted — resource overhead):
Mukhandi, M., Damiao, F., Granjal, J., & Vilela, J. P. (2022); Aanandaram, V., &
Deepalakshmi, P. (2024) — cited as evidence of storage/communication/energy overhead
(Chapter 2, Section 2.5).

**Machine-learning / physical-layer authentication** (future-extension direction):
see `unfiled_references_by_theme.md` for candidate citations once this theme's PDFs are
filed (Chapter 2, Section 2.6).

## References Supporting the Research Methodology Choice

The **Experimental Research Methodology** was selected because the proposed framework
is developed and then tested under normal and attack conditions (repository README,
Section 6 "Research Methodology"). Supporting reference:

- Research Methodology Selection Handbook (course-provided guidance for Group G — IoT
  Security), IDB30102 Research Methodology, UniKL MIIT.

**Verification note:** every citation above is copied from
`../04_References/04References.md`, which the group has already prepared with working
DOIs. Keep that file as the single source of truth — if a citation changes there, update
it here too so the two files never drift apart.

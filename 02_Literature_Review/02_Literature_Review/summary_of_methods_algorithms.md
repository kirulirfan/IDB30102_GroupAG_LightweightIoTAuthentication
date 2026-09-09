# Summary of Methods / Algorithms Identified from Previous Studies

Drawn from Sections 2.3-2.6 of the Research Proposal (Chapter 2), with real citations
now matched to the PDFs filed in `01_Research_Papers/` (see
`paper_theme_citation_mapping.csv` for the full file-to-citation mapping).

## PUF-Based Authentication (17/50 studies)
- Challenge-response pair (CRP) generation from hardware-specific physical variation
  (Kumar & Mondal, 2024; Princess & Premarathne, 2025)
- No need to store a long-term secret key on the device (Manivannan et al., 2024)
- Zero-knowledge-proof-based PUF authentication against strong physical adversaries
  (Petzi et al., 2024)
- Secure-boot and fuzzy-matching combined with PUF (Pham et al., 2023)
- Heterogeneous / joint PUF schemes combining multiple hardware sources
  (Yoon et al., 2023)
- Reported authentication times from under 1 ms to a few ms across these studies

## Lightweight Cryptography and Mutual Authentication (19/50 studies — largest group)
- IP-based node authentication with shared-key encryption (Sarvaiya & Satange, 2022)
- Lightweight authentication/communication protocol minimising cryptographic
  operations (Yodthong & Munlin, 2023)
- Perfect forward and backward secrecy in a lightweight scheme (Nurkifli & Hwang, 2022)
- Energy-efficient key establishment for heterogeneous device clusters (Arora et al., 2022)
- Device-to-device (D2D) lightweight authentication (Alzahrani, 2025)
- Cross-domain mutual identity authentication (LCDMA) (Gong et al., 2023)
- Anonymity-preserving user authentication for healthcare IoT (Masud et al., 2022)
- Privacy-preserving mutual authentication with forward secrecy for IoT-Edge-Cloud
  (Seifelnasr et al., 2024)
- Provable-secure anonymous device authentication (Ren et al., 2024)
- Secure, lightweight cloud-assisted user authentication (Wang et al., 2023)

**This is the theme the proposed framework is built on**, using: device registration,
identity checking, mutual challenge-response authentication, HMAC verification,
nonce/timestamp freshness checking, session-key establishment, authenticated
encryption, message-integrity checking, replay protection and security-event logging
(Chapter 1, Section 1.7 Scope; repository README "Proposed Solution").

## Blockchain-Based Authentication (8/50 studies)
- Consensus-based device identity management (Mukhandi et al., 2022)
- Blockchain-based digital identity for 5G IoT networks (Aanandaram & Deepalakshmi, 2024)
- Blockchain-based mutual authentication for decentralised healthcare IoT
  (Chen et al., 2024)
- Key management with chaotic scrambling on blockchain (Zheng et al., 2023)
- Privacy-preserving blockchain authentication for satellite-assisted IoT
  (Wang et al., 2022)

## Machine-Learning and Physical-Layer Authentication (10/50 studies)
No PDFs are filed under this theme in `01_Research_Papers/` yet. Candidate papers
already in the verified reference list (see `unfiled_references_by_theme.md`) include
Random Forest-based device authentication (Chanal & Kakkasageri, 2023), clock-skew
fingerprinting (Shang et al., 2024), and RAM-trace representation learning
(Iqbal et al., 2024) — these should be filed into
`01_Research_Papers/05_ML_and_PhysicalLayer_Authentication/` to complete this theme's
evidence.

## Why Lightweight Cryptography + Mutual Authentication Was Selected
As concluded in Chapter 2 (Section 2.7.1), this theme gives the best balance between
security and the limited resources of IoT devices, which matches this proposal's aim of
protecting resource-constrained IoT devices "while maintaining acceptable computational
and communication performance" (Chapter 1, Research Aim).

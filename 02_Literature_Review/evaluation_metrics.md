# Evaluation Metrics Identified from Previous Research

Drawn from Section 2.7.2 of the Research Proposal (Chapter 2), mapped to the metrics
this project's own evaluation plan will use (Chapter 3 / repository README, Sections
7.4-7.5).

## Metrics Used by Prior Studies, by Theme

| Theme | Metrics Commonly Used in Prior Studies |
|---|---|
| PUF-based authentication | Authentication time, reliability, uniqueness, error rate |
| Blockchain-based authentication | Transaction time, communication cost, storage, scalability |
| Lightweight cryptography and mutual authentication | Processing cost, communication cost, authentication time, resistance to replay/impersonation/man-in-the-middle attacks |
| Machine-learning and physical-layer authentication | Accuracy, precision, recall, F1-score, false-positive rate |

## Metrics Adopted for This Proposal

Because this research is built on the **lightweight cryptography and mutual
authentication** theme, and must also address Gap 2.8.4 (balancing security and
resource usage), the following metrics were selected — directly matching the project's
own Proposed Evaluation Plan:

**Performance metrics:**
- Authentication time
- Processing time
- Communication delay / message overhead
- Memory usage
- Computational cost

**Security metrics:**
- Authentication success
- Impersonation detection
- Replay detection
- Tampering detection
- Message integrity
- Data protection (confidentiality)

These metrics let the proposed framework be compared against a basic (unsecured)
baseline on **both** security effectiveness and resource cost at the same time — which
Chapter 2 identifies as something prior studies rarely did consistently (Gap 2.8.4).

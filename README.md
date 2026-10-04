# X-Wing Hybrid Key Encapsulation Mechanism (KEM)

An implementation of the **X-Wing hybrid key exchange pipeline** combining classical elliptic curve cryptography (**X25519**) and post-quantum lattice-based cryptography (**ML-KEM-768**) bound together by a **SHA3-256** combiner function. This configuration ensures IND-CCA2 security as long as at least one underlying primitive remains secure.

## 📂 Project Architecture
* `xwing.py`: Core algorithm architecture hosting KeyGen, Encaps, and Decaps mechanisms.
* `test_xwing.py`: Robust automated unittest validation checking edge cases and ciphertext corruption.
* `benchmark.py`: Performance harness computing algorithmic speed across 1,000 continuous iterations.
* `demo.py`: Interactive execution profile visualizing an end-to-end handshake simulation between Alice and Bob.
* `requirements.txt`: Project library dependencies (`cryptography` and `kyber-py`).

## 🚀 Quick Start Guide

### 1. Environment Setup
Install the necessary cryptographic primitive dependencies using pip:
```bash
pip install -r requirements.txt
```

### 2. Run the Simulation Handshake
Visualize the step-by-step key exchange pipeline between Alice and Bob:
```bash
python demo.py
```

### 3. Run Performance Benchmarks
Calculate operational processing latency directly inside your terminal panel:
```bash
python benchmark.py
```

### 4. Execute the Test Suite
Run the automated verification suite to validate correctness, structural key lengths, and error limits:
```bash
python -m unittest test_xwing.py
```

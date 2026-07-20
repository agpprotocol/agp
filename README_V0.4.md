# AGP v0.4 — Signed Cross-Language Conformance Suite

This package preserves all AGP v0.3 semantic tests and adds Ed25519 signed
envelopes verified independently by Python and Go.

## What it tests

- Python/Go semantic regression: 260 vectors
- Ed25519 cross-language verification
- canonical signed payloads
- tampered payload rejection
- tampered signature rejection
- unknown/wrong key rejection
- key revocation
- envelope expiration
- replay detection
- byte-identical verification receipts

## macOS setup

```bash
cd ~/Downloads/agp_signed_conformance_suite_v0.4
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-v0.4.txt
python3 run_all_v0.4.py
```

Expected output:

```text
Generated 260 vectors
AGP v0.3 Conformance: 260/260 passed
Byte-identical across Python and Go: True
Generated 10 signed vectors
AGP v0.4 Signed Conformance: 10/10 passed
Byte-identical verification receipts: True
AGP v0.4 COMPLETE: semantic and signed conformance passed
```

## Important scope note

The Go verifier is independent. Deterministic test keys and vectors are generated
by the suite so both implementations receive identical inputs. A later profile
should add vectors emitted natively by each implementation and transparency logs.

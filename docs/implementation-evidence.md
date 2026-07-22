# AGP Implementation Evidence Inventory

Status: Automatically generated working document

This inventory maps security topics to repository files containing
potential implementation, specification, vector, or test evidence.

A match does not by itself prove correct implementation.

## payload_tampering

- `benchmark/agp/agp_engine.py`
- `benchmark/scenarios/01_clean.json`
- `benchmark/scenarios/02_omitted_ballot.json`
- `benchmark/scenarios/03_altered_ballot.json`
- `benchmark/scenarios/04_reordered_history.json`
- `benchmark/scenarios/05_truncated_history.json`
- `benchmark/scenarios/06_stale_evidence.json`
- `benchmark/scenarios/07_revoked_voter.json`
- `benchmark/scenarios/08_replaced_root.json`
- `benchmark/scenarios/09_duplicate_ballot.json`
- `benchmark/tools/generate_scenarios.py`
- `docs/attack-matrix.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `examples/120_second_demo/README.md`
- `examples/120_second_demo/demo.py`
- `go/cmd/agp-resolver/main.go`
- `python/resolver.py`
- `signed/tools/generate_signed_vectors.py`
- `signed/vectors/003_tampered_payload.json`
- `spec/AGP-CONFORMANCE-PROFILE-0.3.md`
- `transparency/tools/generate_vectors.py`
- `transparency/vectors/001_valid_log.json`
- `transparency/vectors/002_tampered_event.json`
- `transparency/vectors/003_deleted_entry.json`
- `transparency/vectors/004_reordered_entries.json`
- `transparency/vectors/006_forked_history.json`
- `transparency/vectors/007_replaced_hash.json`
- `transparency/vectors/008_duplicate_index.json`

## signature_validation

- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `signed/go/cmd/agp-signed/main.go`
- `signed/python/signed.py`
- `signed/tools/generate_signed_vectors.py`
- `signed/vectors/004_tampered_signature.json`
- `signed/vectors/005_unknown_key.json`
- `signed/vectors/010_wrong_public_key.json`

## replay

- `CHANGELOG.md`
- `README.md`
- `README_V0.4.md`
- `benchmark/spec/BENCHMARK-0.1.md`
- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `examples/120_second_demo/README.md`
- `signed/go/cmd/agp-signed/main.go`
- `signed/python/signed.py`
- `signed/tools/generate_signed_vectors.py`
- `signed/vectors/001_python_signed_valid.json`
- `signed/vectors/002_go_key_signed_valid.json`
- `signed/vectors/003_tampered_payload.json`
- `signed/vectors/004_tampered_signature.json`
- `signed/vectors/005_unknown_key.json`
- `signed/vectors/006_expired_envelope.json`
- `signed/vectors/007_replay.json`
- `signed/vectors/008_revoked_key.json`
- `signed/vectors/009_key_not_yet_valid.json`
- `signed/vectors/010_wrong_public_key.json`

## revocation

- `CHANGELOG.md`
- `README.md`
- `README_V0.4.md`
- `benchmark/REPORT.md`
- `benchmark/agp/agp_engine.py`
- `benchmark/scenarios/07_revoked_voter.json`
- `benchmark/tools/generate_scenarios.py`
- `docs/ARCHITECTURE.md`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `docs/whitepaper/README.md`
- `examples/120_second_demo/README.md`
- `go/cmd/agp-resolver/main.go`
- `python/resolver.py`
- `signed/go/cmd/agp-signed/main.go`
- `signed/python/signed.py`
- `signed/tools/generate_signed_vectors.py`
- `signed/vectors/008_revoked_key.json`
- `signed/vectors/009_key_not_yet_valid.json`
- `spec/AGP-CONFORMANCE-PROFILE-0.3.md`
- `tools/generate_vectors.py`

## duplicate_evidence

- `benchmark/agp/agp_engine.py`
- `benchmark/scenarios/09_duplicate_ballot.json`
- `benchmark/spec/BENCHMARK-0.1.md`
- `benchmark/tools/generate_scenarios.py`
- `docs/BENCHMARK.md`
- `docs/THREAT_MODEL.md`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `examples/deployment_approval/README.md`
- `spec/AGP-CONFORMANCE-PROFILE-0.3.md`
- `transparency/go/cmd/agp-log/main.go`
- `transparency/python/transparency.py`
- `transparency/spec/AGP-TRANSPARENCY-LOG-0.5.md`
- `transparency/tools/generate_vectors.py`
- `transparency/vectors/008_duplicate_index.json`

## equivocation

- `docs/ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `go/cmd/agp-resolver/main.go`
- `python/resolver.py`
- `tools/generate_vectors.py`
- `transparency/tools/generate_vectors.py`
- `transparency/vectors/006_forked_history.json`

## cross_language

- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/protocol_proposal.yml`
- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/workflows/conformance.yml`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `GOVERNANCE.md`
- `README.md`
- `README_V0.4.md`
- `ROADMAP.md`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `examples/120_second_demo/README.md`
- `examples/120_second_demo/demo.py`
- `examples/deployment_approval/README.md`
- `run_all_v0.4.py`
- `run_all_v0.5.py`
- `signed/spec/AGP-SIGNED-CONFORMANCE-0.4.md`
- `signed/tools/generate_signed_vectors.py`
- `signed/tools/run_signed_conformance.py`
- `spec/AGP-CONFORMANCE-PROFILE-0.3.md`
- `tools/run_conformance.py`
- `transparency/spec/AGP-TRANSPARENCY-LOG-0.5.md`
- `transparency/tools/run_transparency.py`

## expiration

- `CHANGELOG.md`
- `README.md`
- `README_V0.4.md`
- `benchmark/agp/agp_engine.py`
- `benchmark/scenarios/06_stale_evidence.json`
- `benchmark/tools/generate_scenarios.py`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `go/cmd/agp-resolver/main.go`
- `python/resolver.py`
- `signed/go/cmd/agp-signed/main.go`
- `signed/python/signed.py`
- `signed/tools/generate_signed_vectors.py`
- `signed/vectors/001_python_signed_valid.json`
- `signed/vectors/002_go_key_signed_valid.json`
- `signed/vectors/003_tampered_payload.json`
- `signed/vectors/004_tampered_signature.json`
- `signed/vectors/005_unknown_key.json`
- `signed/vectors/006_expired_envelope.json`
- `signed/vectors/007_replay.json`
- `signed/vectors/008_revoked_key.json`
- `signed/vectors/009_key_not_yet_valid.json`
- `signed/vectors/010_wrong_public_key.json`
- `tools/generate_vectors.py`

## transparency

- `CHANGELOG.md`
- `README.md`
- `README_V0.4.md`
- `ROADMAP.md`
- `benchmark/spec/BENCHMARK-0.1.md`
- `docs/ARCHITECTURE.md`
- `docs/attack-matrix.md`
- `docs/threat-model.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.1.md`
- `docs/whitepaper/AGP_Whitepaper_v0.9.2.md`
- `docs/whitepaper/README.md`
- `examples/120_second_demo/README.md`
- `run_all_v0.5.py`
- `transparency/python/transparency.py`
- `transparency/spec/AGP-TRANSPARENCY-LOG-0.5.md`
- `transparency/tools/generate_vectors.py`
- `transparency/tools/run_transparency.py`
- `transparency/vectors/003_deleted_entry.json`
- `transparency/vectors/004_reordered_entries.json`
- `transparency/vectors/005_truncated_log.json`

## policy_binding

- `docs/attack-matrix.md`
- `docs/threat-model.md`

## Verified suite run — 2026-07-22

Executed locally using Python 3.13 with the `cryptography` dependency installed.

Results:

- AGP v0.3 semantic conformance: 260/260 passed.
- Python and Go semantic outputs were byte-identical.
- AGP v0.4 signed conformance: 10/10 passed.
- Python and Go verification receipts were byte-identical.
- AGP v0.5 transparency conformance: 8/8 passed.
- Python and Go audit receipts were byte-identical.
- Full v0.5 suite completed successfully.

Command:

```text
python run_all_v0.5.py
```

This confirms the current repository implements interoperable semantics,
Ed25519 signature verification, and transparency-log validation for the
published conformance vectors.

It does not by itself prove resistance to all attacks listed in the attack
matrix.

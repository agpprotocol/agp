# Phase 6C-3 — Signed Decision Context Go v0.2.0

Phase 6C-3 prepares the second public release of:

    agpprotocol.org/agp/signed-decision-context

The release tag is:

    signed_decision_context/go/v0.2.0

## Version rationale

Version v0.1.0 introduced the reusable public Go verification API.

Version v0.2.0 adds a substantial backward-compatible public capability:

- deterministic Signed Decision Context creation;
- deterministic signature append;
- Ed25519 private-key parsing;
- canonical output bytes;
- stable typed signing failures;
- the `agp-signed-decision-context-sign` command.

The existing `verify` API remains compatible.

## Public packages

    agpprotocol.org/agp/signed-decision-context/sign
    agpprotocol.org/agp/signed-decision-context/verify

## Installation

After the release tag is published:

    go get agpprotocol.org/agp/signed-decision-context@v0.2.0

## Release validation

Before tagging:

    python signed_decision_context/tools/test_sdc_go_public_api_contract.py
    python signed_decision_context/tools/run_go_signer_parity.py

After merging this preparation commit, create the annotated tag:

    git tag -a signed_decision_context/go/v0.2.0 \
      -m "Signed Decision Context Go v0.2.0"

    git push origin signed_decision_context/go/v0.2.0

Then verify from a clean external module without `replace`.

# Phase 6B-4 — Signed Go Quick Start

Phase 6B-4 adds a self-contained public Go example for verified policy
evaluation through `tpe.EvaluateSigned`.

The example embeds:

- one valid Ed25519 Signed Decision Context;
- its public verification keyring;
- one root policy requiring the verified signer.

It verifies the signature, projects the authenticated Decision Context, and
evaluates the policy through the stable public Go API.

Run:

    cd trust_primitive_engine/go
    go run ./examples/signed-evaluation

Expected marker:

    SIGNED_TPE_QUICK_START_PASS status=satisfied signer=authority:legal

The example imports only the public `tpe` package and contains no private key
material.

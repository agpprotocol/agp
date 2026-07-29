# Signed Decision Context

The package currently provides:

- normative draft specification;
- Signature Statement JSON Schema;
- Signed Decision Context JSON Schema;
- Python structural validator;
- Stage 1 structural conformance runner;
- Python Ed25519 verifier;
- persistent Stage 2 cryptographic vectors;
- Stage 2 cryptographic conformance runner.

The Schema Registry entries remain reserved.

## Requirements

Install:

    python -m pip install jsonschema 'cryptography>=42.0'

## Stage 1 structural conformance

From the repository root:

    python signed_decision_context/tools/run_conformance.py

## Stage 2 cryptographic vectors

Generate the deterministic Ed25519 vectors:

    python signed_decision_context/tools/generate_crypto_vectors.py

Run the persistent cryptographic conformance suite:

    python signed_decision_context/tools/run_crypto_conformance.py

The vector generator uses deterministic private-key seeds only for
conformance testing. Those keys must never be used outside the test suite.

Each cryptographic vector consists of:

    NNN_name.input.json
    NNN_name.keyring.json
    NNN_name.meta.json

The vector manifest is:

    signed_decision_context/vectors/manifest.json

## Canonicalization

The structural validator, cryptographic verifier and conformance tools import
the repository's normative implementation directly from:

    canonicalization/python/canonicalize.py

Decision Context digests and Signature Statement bytes therefore use the same
AGP Canonicalization 0.7 implementation exercised by the canonicalization
conformance suite.

Ed25519 signatures are calculated over:

    AGP-C14N(signature statement)

They are not calculated over ordinary JSON serialization.

## Verification keys

Stage 2 currently resolves verification keys from an external keyring.

The keyring format contains:

- signer_id
- key_id
- algorithm
- public_key

The public key is encoded as unpadded base64url.

Key lifecycle, revocation, trust roots and authorization policy remain outside
this implementation stage.

## Go signing and verification

The Go module provides a public deterministic signer and verifier:

    cd signed_decision_context/go

    go run ./cmd/agp-signed-decision-context-sign \
      context.json \
      --private-key private-key.json \
      --signer-id authority:legal \
      --key-id key:legal:2026-q3 \
      --signature-id sig:legal:0001 \
      --signed-at 2026-07-28T20:00:00Z \
      --output signed-context.json

    go run ./cmd/agp-signed-decision-context-verify \
      signed-context.json \
      --keyring keyring.json

To append another signature, pass an existing Signed Decision Context and add
`--append`.

Install the public Go module release with:

    go get agpprotocol.org/agp/signed-decision-context@v0.2.0

The public Go packages are:

    agpprotocol.org/agp/signed-decision-context/sign
    agpprotocol.org/agp/signed-decision-context/verify

It exposes `ParsePrivateKey`, `Create`, `Append`, `CanonicalBytes`, and stable
typed signing errors through `ErrorCode`.

Private Ed25519 material must remain in the signing environment. Verification
uses only the Signed Decision Context and its public keyring.

Run the permanent Python/Go signer parity guard with:

    python signed_decision_context/tools/run_go_signer_parity.py

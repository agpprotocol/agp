# Phase 6C-2 — Public Go signer

Phase 6C-2 adds public, deterministic creation and append signing for
AGP Signed Decision Context versions 1, 2, and 3.

## Public API

The `sign` package exposes:

- `ParsePrivateKey`
- `Create`
- `Append`
- `CanonicalBytes`
- typed signing errors through `ErrorCode`

The command-line entry point is:

    go run ./cmd/agp-signed-decision-context-sign

## Signing boundary

Private Ed25519 seeds belong only in the signing environment. Consumers and
verifiers receive the Signed Decision Context and a public verification
keyring; they do not receive private signing material.

## Determinism

The Go signer uses the same canonical JSON representation, SHA-256 context
digest, Signature Statement structure, unpadded base64url encoding, Ed25519
signature bytes, and deterministic signature ordering as the Python signer.

The permanent parity guard verifies:

1. byte-identical Python/Go creation;
2. byte-identical Python/Go append;
3. deterministic repeated Go output;
4. verification of both Go-produced signatures by the Go verifier.

## Validation

    python signed_decision_context/tools/run_go_signer_parity.py

Expected result:

    AGP Signed Decision Context Go signer parity: 4/4 passed

# External Go integration

This directory demonstrates the public Trust Primitive Engine Go integration
boundary.

## Flow

    Decision Context
    -> signing
    -> Signed Decision Context
    -> public keyring
    -> trust policy
    -> tpe.EvaluateSigned
    -> Evaluation or typed error

## Install

Add the public module to an external Go project:

    go get agpprotocol.org/agp/trust-primitive-engine@v0.2.1

Import:

    import "agpprotocol.org/agp/trust-primitive-engine/tpe"

No replace directive is required.

## Satisfied example

Run from the TPE Go module root:

    go run ./examples/external-integration/satisfied

Expected output:

    EXTERNAL_TPE_SATISFIED_PASS status=satisfied signer=authority:legal

The example verifies the Ed25519 signature before evaluating the policy.

## Rejected example

Run:

    go run ./examples/external-integration/rejected

Expected output:

    EXTERNAL_TPE_REJECTED_PASS code=SIGNATURE_VERIFICATION_FAILED

Applications should branch on `tpe.ErrorCode(err)`. They should not depend on
human-readable error text.

## Signing boundary

The Go integration consumes serialized Signed Decision Context and keyring
JSON through `tpe.EvaluateSigned`.

The repository currently provides the signing CLI in Python:

    python signed_decision_context/python/sign_decision_context.py       decision-context.json       --private-key private-key.json       --signer-id authority:legal       --key-id key:authority-legal:2026-q3       --signature-id sig:authority-legal:0001       --signed-at 2026-07-22T20:00:00Z       --output signed-context.json

Private keys belong only in the signing environment. Consumers receive the
Signed Decision Context and the corresponding public keyring.

## Policy outcomes and verification errors

An `Evaluation` with status `unsatisfied` means verification succeeded but the
authenticated context did not satisfy the policy.

A non-nil error means the input could not be safely evaluated. Use:

    code, ok := tpe.ErrorCode(err)

Examples include invalid JSON, unknown keys, unsupported algorithms, malformed
signatures, signature verification failure, and policy binding mismatches.

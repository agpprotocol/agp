# Phase 6B-5 — Trust Primitive Engine Go v0.2.1

Phase 6B-5 prepares the public patch release:

    agpprotocol.org/agp/trust-primitive-engine v0.2.1

## Release scope

This patch release adds the signed public Go quick start introduced in
Phase 6B-4.

The example demonstrates end-to-end use of `tpe.EvaluateSigned` with:

- a valid Ed25519 Signed Decision Context;
- a public verification keyring;
- a root policy requiring the authenticated signer;
- a deterministic satisfied result.

Expected marker:

    SIGNED_TPE_QUICK_START_PASS status=satisfied signer=authority:legal

## Compatibility

The public Go API and module identity are unchanged from v0.2.0.

The module continues to depend on:

    agpprotocol.org/agp/signed-decision-context v0.1.0

No replace directives are present.

## Version decision

The release is v0.2.1 rather than v0.3.0 because it adds documentation,
examples, and release validation without changing the public API or runtime
semantics.

## Release procedure

After the preparation pull request is merged into main, create and push:

    trust_primitive_engine/go/v0.2.1

Then verify the release from a clean external Go module without replace
directives.

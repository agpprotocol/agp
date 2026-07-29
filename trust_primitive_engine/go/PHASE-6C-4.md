# Phase 6C-4 — Public Go signed end-to-end integration

Phase 6C-4 validates the two independently released public Go modules together:

    agpprotocol.org/agp/signed-decision-context v0.2.0
    agpprotocol.org/agp/trust-primitive-engine v0.2.1

The external workflow is:

    Decision Context
    → sign.Create
    → sign.Append
    → Signed Decision Context
    → tpe.EvaluateSigned
    → satisfied evaluation

## Version selection

Trust Primitive Engine v0.2.1 declares Signed Decision Context v0.1.0 as its
minimum dependency.

The external consumer explicitly requires Signed Decision Context v0.2.0.
Go minimal version selection therefore resolves the effective dependency to
v0.2.0 while preserving TPE v0.2.1.

## Permanent checks

The guard verifies:

1. both public modules resolve through the public Go module path;
2. the external module contains no `replace` directive;
3. effective versions are SDC v0.2.0 and TPE v0.2.1;
4. public `sign.Create` succeeds;
5. public `sign.Append` succeeds;
6. `tpe.EvaluateSigned` returns `satisfied`;
7. a tampered signature returns `SIGNATURE_VERIFICATION_FAILED`;
8. the consumer imports only public packages.

Run:

    python trust_primitive_engine/tools/test_public_go_signed_end_to_end.py

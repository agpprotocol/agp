# Public Go compatibility

This document records the current supported public Go release combination.

| Component | Module | Current release |
|---|---|---:|
| Trust Primitive Engine | `agpprotocol.org/agp/trust-primitive-engine` | `v0.2.2` |
| Signed Decision Context | `agpprotocol.org/agp/signed-decision-context` | `v0.2.0` |

## Supported combination

    agpprotocol.org/agp/trust-primitive-engine v0.2.2
    agpprotocol.org/agp/signed-decision-context v0.2.0

TPE v0.2.2 directly requires SDC v0.2.0.

A clean external consumer can install only TPE:

    go get agpprotocol.org/agp/trust-primitive-engine@v0.2.2

Go then resolves SDC v0.2.0 transitively.

No `replace` directive is required.

## Public workflow

The supported integrated workflow is:

    Decision Context
    → sign.Create
    → sign.Append
    → Signed Decision Context
    → tpe.EvaluateSigned
    → deterministic evaluation

The permanent end-to-end guard is:

    python trust_primitive_engine/tools/test_public_go_signed_end_to_end.py

Historical phase documents continue to describe the release combinations that
were current when those phases were completed.

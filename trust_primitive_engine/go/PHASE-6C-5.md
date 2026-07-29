# Phase 6C-5 — Trust Primitive Engine Go v0.2.2

Phase 6C-5 prepares the patch release:

    agpprotocol.org/agp/trust-primitive-engine v0.2.2

Release tag:

    trust_primitive_engine/go/v0.2.2

## Dependency alignment

Trust Primitive Engine Go now declares:

    agpprotocol.org/agp/signed-decision-context v0.2.0

TPE v0.2.1 still declared SDC v0.1.0 because that was the latest available
version when the dependency was introduced.

SDC v0.2.0 adds the public signing API while preserving the verification API
used by TPE.

## Version rationale

This is a patch release because:

- the public TPE API is unchanged;
- evaluation semantics are unchanged;
- serialized inputs and outputs are unchanged;
- no new TPE functionality is introduced;
- the release aligns the minimum public SDC dependency with the current
  compatible release.

## Release contract

The permanent guard verifies:

1. TPE declares SDC v0.2.0;
2. the public module contains no `replace`;
3. `go.sum` is aligned to SDC v0.2.0;
4. all TPE Go packages pass tests and vet;
5. an external consumer resolves SDC v0.2.0;
6. signed evaluation returns `satisfied`;
7. the consumer imports only the public TPE package.

Before tagging:

    python trust_primitive_engine/tools/test_tpe_go_v022_release_contract.py

After merge, create the annotated tag:

    git tag -a trust_primitive_engine/go/v0.2.2 \
      -m "Trust Primitive Engine Go v0.2.2"

Then verify the release from a clean external module without `replace`.

# Phase 6C-6 — Public Go release alignment

Phase 6C-6 aligns current documentation and permanent integration guards with
the published public Go releases:

    agpprotocol.org/agp/trust-primitive-engine v0.2.2
    agpprotocol.org/agp/signed-decision-context v0.2.0

## Scope

This phase updates only current public references.

Historical phase documents remain unchanged because they describe the versions
that were current when those phases were completed.

## Permanent checks

The alignment guard verifies:

1. the end-to-end guard pins TPE v0.2.2 and SDC v0.2.0;
2. TPE declares SDC v0.2.0;
3. the public TPE module contains no `replace`;
4. the external integration guide installs TPE v0.2.2;
5. the TPE README documents the current public pair;
6. the public compatibility matrix is complete.

Run:

    python trust_primitive_engine/tools/test_public_go_release_alignment.py

The integrated public workflow remains validated by:

    python trust_primitive_engine/tools/test_public_go_signed_end_to_end.py

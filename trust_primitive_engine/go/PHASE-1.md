# Go TPE Phase 1 Core Types

## Scope

Phase 1 introduces reusable core building blocks without moving evaluation,
validation, or CLI behavior from the bounded reproducer.

Implemented:

- stable `tpe.Code`;
- typed `tpe.Error`;
- `errors.Is`, `errors.As`, and wrapped-cause support;
- validated internal policy identity;
- deterministic requirement and policy result invariants;
- compact sorted-key JSON serialization;
- canonical SHA-256 digest calculation;
- focused Go unit tests.

## Boundary

The public `tpe.Evaluate` API is not introduced in this phase.

The internal result types are not yet normative serialization models. They
establish invariants required by later extraction phases.

The bounded `agp-tpe26-reproduce` command remains unchanged.

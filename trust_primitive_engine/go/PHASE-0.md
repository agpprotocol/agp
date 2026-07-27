# Go TPE Phase 0 Decisions

## Status

Phase 0 establishes module identity and package boundaries without moving
normative logic from `cmd/agp-tpe26-reproduce`.

## Module identity

```text
agpprotocol.org/agp/trust-primitive-engine
```

This follows the repository convention already used by the Decision Context,
Signed Decision Context, and registry Go modules.

## Package visibility

The only intended stable public package is:

```text
agpprotocol.org/agp/trust-primitive-engine/tpe
```

All implementation packages begin under `internal/`. They may be promoted only
through a reviewed API decision after their contracts stabilize.

## Initial API input boundary

Phase 0 does not freeze the `tpe.Evaluate` signature. The first implementation
may accept decoded JSON-compatible values behind the public facade while typed
models remain internal.

## Schema strategy

The initial engine will use equivalent native Go validators proven against the
authoritative Python/schema behavior. Embedding or generating directly from
JSON Schema remains a later implementation decision.

## Signed Decision Context boundary

Signed Decision Context remains a sibling Go module:

```text
agpprotocol.org/agp/signed-decision-context
```

Before TPE integration, its verifier must be extracted from the CLI into an
importable package. The TPE module will consume that package rather than copy
verification logic.

## Versioning

No reusable Go library release is declared in Phase 0. Semantic versioning
begins only when the public `tpe` API is explicitly stabilized and tagged.

## Compatibility constraint

The bounded reproducer remains unchanged except for building inside the renamed
module. Existing frozen outputs and all registered Python/Go suites remain
authoritative.

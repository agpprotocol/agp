# Phase 6B-2 — External Go Module Installability

Phase 6B-2 publishes the vanity-import metadata required to resolve the
public Go modules from `agpprotocol.org`.

Public module paths:

- `agpprotocol.org/agp/trust-primitive-engine`
- `agpprotocol.org/agp/signed-decision-context`

Repository backend:

- `https://github.com/agpprotocol/agp`

Module subdirectories:

- `trust_primitive_engine/go`
- `signed_decision_context/go`

Because these modules reside in repository subdirectories whose physical
paths differ from their public vanity paths, public vanity resolution uses
the four-field `go-import` metadata format with an explicit subdirectory.

Go 1.25 or later is required for public vanity resolution. The module source
continues to use the Go 1.22 language baseline.

The existing v0.1.0 tags predate these metadata endpoints. A new module
release must be created only after the endpoints are deployed and externally
verified.

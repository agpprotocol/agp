# Phase 6B-3 — Trust Primitive Engine Go v0.2.0

Phase 6B-3 prepares the second public Go module release of the Trust Primitive
Engine.

Release:

- `trust_primitive_engine/go/v0.2.0`

Dependency:

- `agpprotocol.org/agp/signed-decision-context v0.1.0`

Signed Decision Context remains at v0.1.0 because its module source has not
changed since that release.

The obsolete repository-local replace directive is removed. Dependency
resolution now uses the public vanity-import endpoint at agpprotocol.org.

The v0.2.0 TPE release includes:

- complete 27-primitive Go evaluation parity;
- recursive mixed composition evaluation;
- recursive policy-reference evaluation;
- nested matched-signer projection fix;
- frozen parity coverage;
- stable public Go API contract;
- runnable public quick start;
- public vanity-module installability.

# Phase 6D-1 — Go release integrity

Phase 6D-1 adds a permanent integrity gate for the current public Go
releases:

- Signed Decision Context Go v0.2.0
- Trust Primitive Engine Go v0.2.2

No new release or public tag is created by this phase.

## Integrity workflow

The dedicated workflow is:

```text
.github/workflows/go-release-integrity.yml
```

For both public Go modules it runs:

```text
go mod verify
go test ./...
go vet ./...
govulncheck ./...
```

The vulnerability scanner is pinned to:

```text
golang.org/x/vuln/cmd/govulncheck@v1.6.0
```

The workflow uses Go 1.22.x, read-only repository permissions, a bounded
timeout, full tag history, and concurrency cancellation.

## Public tag integrity

These public release references must remain annotated Git tags:

```text
signed_decision_context/go/v0.2.0
trust_primitive_engine/go/v0.2.2
```

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_go_release_integrity_contract.py
```

Expected marker:

```text
AGP Go release integrity contract: 8/8 passed
```

The eight checks increase the complete development validation total from
948 to 956.

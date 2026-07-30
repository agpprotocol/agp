# Phase 6D-6D — Go module dependency integrity

Phase 6D-6D makes the repository's Go module graph an executable
integrity contract.

## Module inventory

The repository contains nine Go modules. Eight modules have no external
dependencies and therefore do not require `go.sum`. The Trust Primitive
Engine module retains the only checksum file.

## Verification

The permanent verifier checks every module in an isolated temporary copy:

```text
go mod verify
go list -m all
go mod tidy
```

The tidy check requires `go.mod` and `go.sum` to remain byte-stable.

The default public dependency infrastructure is explicit:

```text
GOPROXY=https://proxy.golang.org,direct
GOSUMDB=sum.golang.org
```

Checksum verification must not be disabled.

## CI integration

Go Release Integrity runs:

```text
python trust_primitive_engine/tools/verify_go_module_dependency_integrity.py
```

The verifier executes 27 checks across nine modules.

## Permanent contract

```text
trust_primitive_engine/tools/test_go_module_dependency_integrity_contract.py
```

Expected markers:

```text
AGP Go module dependency integrity: 27/27 passed
AGP Go module dependency integrity contract: 12/12 passed
```

The contract contributes twelve checks, increasing complete TPE
development validation from 1027 to 1039 checks.

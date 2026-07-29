# Phase 6D-4 — Official GitHub Actions immutable pinning

Phase 6D-4 removes the remaining moving major-version references from
the repository's official setup actions.

## Scope

The phase covers nineteen references across eight workflows:

```text
actions/checkout      8 references
actions/setup-go      5 references
actions/setup-python  6 references
```

Each action is pinned to the reviewed immutable commit:

```text
actions/checkout
  3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1

actions/setup-go
  b7ad1dad31e06c5925ef5d2fc7ad053ef454303e  # v7.0.0

actions/setup-python
  5fda3b95a4ea91299a34e894583c3862153e4b97  # v7.0.0
```

## Preserved behavior

The phase changes only action references and their readable version
comments. Existing workflow inputs, language versions, permissions,
triggers, timeouts, concurrency, checkout depth, release handling,
and toolchain-selection behavior remain unchanged.

The Phase 6D-2 runtime contract and the Go release integrity contract
are updated to validate the immutable references.

## Permanent contract

The repository contract is:

```text
trust_primitive_engine/tools/test_official_actions_pinning_contract.py
```

It validates eight requirements:

1. the official setup action inventory is exact;
2. all official setup references use full commit SHAs;
3. all checkout references match the reviewed `v7.0.1` commit;
4. all setup-go references match the reviewed `v7.0.0` commit;
5. all setup-python references match the reviewed `v7.0.0` commit;
6. moving official setup tags are absent;
7. the reviewed reference count remains nineteen;
8. readable reviewed-version comments remain present.

Expected marker:

```text
AGP official Actions pinning contract: 8/8 passed
```

The contract contributes eight checks to complete TPE development
validation, increasing its expected total from 973 to 981.

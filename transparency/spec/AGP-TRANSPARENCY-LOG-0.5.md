# AGP Transparency Log Profile 0.5

## Purpose

The transparency log makes the governance history independently auditable.
Each entry commits to the previous entry and to its canonical event body.

## Entry format

- `index`
- `timestamp`
- `event_type`
- `event_id`
- `event`
- `previous_hash`
- `entry_hash`

`entry_hash` is:

`SHA-256(canonical_json(entry_without_entry_hash))`

The genesis entry MUST use:

`previous_hash = "GENESIS"`

## Verification

A conforming verifier MUST reject:

- missing indices;
- duplicate indices;
- non-contiguous indices;
- a wrong genesis predecessor;
- a predecessor hash mismatch;
- an entry hash mismatch;
- an event body altered after hashing;
- a reordered sequence;
- a truncated log when an expected checkpoint is supplied;
- a fork when two logs share a checkpoint and then diverge.

## Receipt

Python and Go MUST emit byte-identical verification receipts.

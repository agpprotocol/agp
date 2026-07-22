# AGP Decision Context 0.9

## Status

Draft protocol profile.

This document defines `agp.decision-context/1`. The object describes the
question and immutable inputs presented to an AGP decision process. It MUST
NOT contain a decision result, vote outcome, approval state, execution state,
or transparency-log position.

## 1. Design boundary

A Decision Context answers:

- What proposal is being evaluated?
- Under which policy?
- Which participants are eligible?
- Which evidence and constraints are part of the input?
- When was the context created and, optionally, when does it expire?

It does not answer whether the proposal was accepted or rejected.

## 2. JSON representation

A conforming object has exactly these top-level members:

- `object_type`
- `context_id`
- `created_at`
- `expires_at`
- `policy`
- `proposal`
- `participants`
- `evidence`
- `constraints`

Unknown top-level members MUST be rejected.

### 2.1 object_type

MUST equal:

`agp.decision-context/1`

### 2.2 context_id

An opaque, application-assigned identifier.

It MUST:

- contain between 3 and 128 ASCII characters;
- begin with a lowercase ASCII letter or digit;
- contain only lowercase ASCII letters, digits, `.`, `_`, `:`, and `-`.

The identifier does not prove content identity. Content identity is established
by canonicalization and digesting the complete object.

### 2.3 Timestamps

`created_at` MUST be an RFC 3339 UTC timestamp with whole-second precision:

`YYYY-MM-DDTHH:MM:SSZ`

`expires_at` MUST be either `null` or a timestamp in the same format and MUST
be strictly later than `created_at`.

### 2.4 policy

`policy` has exactly:

- `id`: non-empty protocol identifier;
- `version`: positive JSON safe integer;
- `digest`: lowercase 64-character hexadecimal SHA-256 digest.

### 2.5 proposal

`proposal` has exactly:

- `type`: non-empty protocol identifier;
- `payload`: a JSON object.

The payload is input data only. The members `decision`, `result`, `outcome`,
`accepted`, `approved`, `rejected`, `resolution`, and `execution_state` are
reserved and MUST NOT appear directly inside `proposal.payload`.

### 2.6 participants

`participants` is an array sorted by `id`, with no duplicate identifiers.

Every entry has exactly:

- `id`: protocol identifier;
- `role`: one of `proposer`, `voter`, `reviewer`, `approver`, or `observer`;
- `weight`: positive JSON safe integer.

At least one participant is required.

### 2.7 evidence

`evidence` is an array sorted by `id`, with no duplicate identifiers.

Every entry has exactly:

- `id`: protocol identifier;
- `digest`: lowercase SHA-256 digest;
- `media_type`: lowercase media type such as `application/json`.

The referenced bytes are external to the Decision Context.

### 2.8 constraints

`constraints` is an array sorted by `id`, with no duplicate identifiers.

Every entry has exactly:

- `id`: protocol identifier;
- `kind`: protocol identifier;
- `parameters`: a JSON object.

### 2.9 Number restrictions

All numbers MUST be integers in the JSON safe integer range. Decimal,
exponent, NaN, and Infinity forms MUST be rejected before semantic validation.

### 2.10 JSON restrictions

Implementations MUST reject:

- duplicate JSON object members;
- UTF-8 BOM;
- invalid UTF-8;
- invalid or unpaired Unicode surrogate escapes;
- trailing data after the root value.

## 3. Validation receipt

A validator emits:

```json
{"accepted":true,"detail":null,"error_code":null}
```

or:

```json
{"accepted":false,"detail":"...","error_code":"..."}
```

The stable error codes defined by this draft are:

- `INVALID_JSON`
- `INVALID_OBJECT`
- `UNKNOWN_TOP_LEVEL_MEMBER`
- `INVALID_OBJECT_TYPE`
- `INVALID_CONTEXT_ID`
- `INVALID_TIMESTAMP`
- `INVALID_POLICY`
- `INVALID_PROPOSAL`
- `RESERVED_RESULT_MEMBER`
- `INVALID_PARTICIPANTS`
- `INVALID_EVIDENCE`
- `INVALID_CONSTRAINTS`
- `INVALID_IDENTIFIER`
- `INVALID_SAFE_INTEGER`
- `DUPLICATE_IDENTIFIER`
- `UNSORTED_COLLECTION`

## 4. Registry lifecycle

The registry entry for `agp.decision-context/1` remains `reserved` during this
draft stage. It SHOULD become `active` only after independent implementations
produce identical acceptance decisions and stable error codes over the
official vectors.

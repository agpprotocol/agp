# AGP Signed Decision Context 1.0

Status: Draft  
Object identifier: `agp.signed-decision-context/1`  
Signature statement identifier: `agp.signature-statement/1`  
Canonicalization: `agp-c14n/0.7`  
Digest: `sha-256`

## 1. Scope

This specification defines a self-contained AGP object that embeds one immutable
Decision Context and one or more independent cryptographic attestations over that
context.

It defines:

- the Signature Statement;
- the Signed Decision Context object;
- structural validation;
- deterministic signature ordering;
- duplicate detection;
- digest binding;
- algorithm agility;
- error precedence for structural validation.

It does not define:

- quorum satisfaction;
- signer authorization;
- public-key discovery;
- key revocation semantics;
- transparency-log inclusion;
- decision outcomes;
- execution authorization;
- aggregate or threshold signatures.

## 2. Normative language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as normative requirements.

## 3. Dependencies

A conforming implementation MUST support:

- `agp.decision-context/1`;
- AGP Canonicalization 0.7;
- SHA-256 encoded as 64 lowercase hexadecimal characters;
- registry resolution for signature algorithm identifiers.

## 4. Decision Context digest

For the embedded Decision Context:

```text
context_bytes =
    AGP-C14N-0.7(context)

context_digest =
    SHA-256(context_bytes)
```

The encoded value MUST contain exactly 64 lowercase hexadecimal characters.

## 5. Signature Statement

A Signature Statement has this form:

```json
{
  "object_type": "agp.signature-statement/1",
  "purpose": "decision-context-attestation",
  "context_object_type": "agp.decision-context/1",
  "context_digest": {
    "algorithm": "sha-256",
    "value": "<64 lowercase hexadecimal characters>"
  },
  "signer_id": "authority:legal",
  "key_id": "key:authority-legal:2026-q3",
  "algorithm": "ed25519",
  "signed_at": "2026-07-22T20:00:00Z"
}
```

All fields are REQUIRED.

Unknown fields MUST be rejected.

The signature input is the AGP Canonicalization 0.7 representation of the complete
Signature Statement.

```text
signature_message =
    AGP-C14N-0.7(signature_statement)
```

The `purpose` value MUST be exactly:

```text
decision-context-attestation
```

## 6. Signed Decision Context

A Signed Decision Context has this form:

```json
{
  "object_type": "agp.signed-decision-context/1",
  "context": {
    "object_type": "agp.decision-context/1"
  },
  "context_digest": {
    "algorithm": "sha-256",
    "value": "<64 lowercase hexadecimal characters>"
  },
  "signatures": [
    {
      "signature_id": "sig:authority-legal:0001",
      "statement": {
        "object_type": "agp.signature-statement/1",
        "purpose": "decision-context-attestation",
        "context_object_type": "agp.decision-context/1",
        "context_digest": {
          "algorithm": "sha-256",
          "value": "<64 lowercase hexadecimal characters>"
        },
        "signer_id": "authority:legal",
        "key_id": "key:authority-legal:2026-q3",
        "algorithm": "ed25519",
        "signed_at": "2026-07-22T20:00:00Z"
      },
      "signature": "<unpadded base64url>"
    }
  ]
}
```

All top-level fields are REQUIRED.

Unknown top-level fields MUST be rejected.

The `signatures` array MUST contain at least one entry.

## 7. Context binding

The embedded `context` MUST validate as `agp.decision-context/1`.

The top-level `context_digest` MUST equal the digest recomputed from the canonical
embedded context.

Every Signature Statement MUST contain:

```text
context_object_type = agp.decision-context/1
```

Every Signature Statement context digest MUST equal the top-level context digest.

## 8. Identifiers

The following fields use the common AGP identifier syntax:

- `signature_id`;
- `signer_id`;
- `key_id`;
- signature algorithm identifier.

Identifiers MUST match:

```text
^[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]$
```

The minimum length is 3 characters and the maximum length is 128 characters.

## 9. Time format

`signed_at` MUST be UTC and match exactly:

```text
YYYY-MM-DDTHH:MM:SSZ
```

Fractional seconds and timezone offsets are not permitted in version 1.

The timestamp is signer-asserted unless supported by external trusted-time
evidence.

## 10. Signature encoding

`signature` MUST use unpadded base64url.

Only these characters are permitted:

```text
A-Z a-z 0-9 - _
```

The value MUST NOT contain `=` padding.

The empty string is invalid.

Algorithm-specific signature length validation is performed by the applicable
algorithm profile, not by the generic object schema.

## 11. Signature ordering

Entries MUST be sorted lexicographically by:

```text
(
  statement.signer_id,
  statement.key_id,
  statement.algorithm,
  statement.signed_at,
  signature_id
)
```

Comparisons use Unicode scalar-value order over original string values accepted by
AGP Canonicalization 0.7.

Implementations MUST NOT apply Unicode normalization.

Implementations MUST reject unsorted arrays rather than silently sorting them.

## 12. Duplicate detection

Duplicate `signature_id` values MUST be rejected.

Two entries with the same semantic-attestation tuple MUST be rejected:

```text
(
  statement.context_digest.algorithm,
  statement.context_digest.value,
  statement.signer_id,
  statement.key_id,
  statement.algorithm,
  statement.signed_at
)
```

Two entries with identical statements and identical signature bytes MUST be
rejected even when their `signature_id` values differ.

## 13. Multi-signature semantics

Each signature is independent.

The object does not claim:

- that a quorum was met;
- that a signer was authorized;
- that a policy was satisfied;
- that execution is allowed.

A verifier MUST evaluate each signature independently.

Parallel classical and post-quantum signatures are represented as separate
signature entries.

## 14. Algorithm agility

`statement.algorithm` MUST identify a signature algorithm registered in the AGP
Schema Registry.

The first reference implementation supports `ed25519`.

The generic schema MUST NOT impose universal Ed25519-specific key or signature
lengths.

## 15. Signed object digest

The complete Signed Decision Context may be digested as:

```text
signed_context_digest =
    SHA-256(
        AGP-C14N-0.7(signed_decision_context)
    )
```

This digest changes when any signature entry or embedded context field changes.

It is suitable for transparency records and verification receipts.

## 16. Structural validation order

A structural validator MUST apply checks in this order:

1. JSON parsing restrictions;
2. top-level schema;
3. embedded Decision Context schema;
4. context canonicalization;
5. context digest recomputation;
6. top-level digest comparison;
7. signature-entry schema;
8. statement context binding;
9. signature ordering;
10. duplicate signature identifiers;
11. duplicate statement-and-signature entries;
12. duplicate semantic attestations.

Cryptographic verification is outside Stage 1.

## 17. Structural error codes

A conforming Stage 1 validator MUST emit one of:

- `INVALID_JSON`
- `INVALID_OBJECT_TYPE`
- `UNKNOWN_TOP_LEVEL_MEMBER`
- `INVALID_CONTEXT`
- `INVALID_CONTEXT_DIGEST`
- `CONTEXT_DIGEST_MISMATCH`
- `EMPTY_SIGNATURE_COLLECTION`
- `INVALID_SIGNATURE_COLLECTION`
- `INVALID_SIGNATURE_ENTRY`
- `INVALID_SIGNATURE_STATEMENT`
- `STATEMENT_CONTEXT_TYPE_MISMATCH`
- `STATEMENT_CONTEXT_DIGEST_MISMATCH`
- `UNSORTED_SIGNATURES`
- `DUPLICATE_SIGNATURE_ID`
- `DUPLICATE_ATTESTATION`
- `DUPLICATE_SIGNATURE_ENTRY`
- `INVALID_SIGNATURE_ENCODING`

## 18. Registry state

During Stage 1, `agp.signed-decision-context/1` remains `reserved`.

It MUST NOT be changed to `active` until:

- the normative specification is reviewed;
- JSON Schemas are stable;
- Python conformance passes;
- persistent vectors exist;
- an independent implementation confirms parity.

## 19. Compatibility

AGP 0.6 Signed Envelopes are not valid Signed Decision Context 1 objects.

Compatibility adapters MUST be explicit and MUST NOT silently reinterpret the
historical envelope as this object.

## 20. Security considerations

A valid structure does not prove:

- signature authenticity;
- signer authorization;
- key validity;
- trusted signing time;
- transparency inclusion;
- policy satisfaction.

Those conclusions require later verification layers.

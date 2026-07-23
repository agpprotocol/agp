# AGP Signed Decision Context 1.0 — Design Draft

Status: Design draft  
Target object identifier: `agp.signed-decision-context/1`  
Target signature statement identifier: `agp.signature-statement/1`  
Target verification receipt identifier: `agp.signature-verification-receipt/1`

## 1. Purpose

This document defines the security architecture for cryptographically binding one
or more signer attestations to an immutable AGP Decision Context.

The design separates:

1. the governed input object;
2. signer attestations;
3. key state and key history;
4. quorum or authorization policy;
5. transparency publication;
6. verification receipts;
7. transport envelopes.

The design intentionally does not reuse the AGP 0.6 model in which the transport
envelope itself was the signature input.

## 2. Security objectives

A conforming implementation MUST make it possible to determine:

- which exact Decision Context was attested;
- which signer identifier was asserted;
- which key identifier and algorithm were used;
- which canonical bytes were signed;
- whether the signature is cryptographically valid;
- whether the key was valid for that signer at the declared signing time;
- whether the signature was replayed into another protocol, object type, signer,
  key, algorithm, or signing time;
- whether multiple independent signatures refer to the same context;
- whether a later transparency record refers to the same signed object;
- whether a verification receipt is reproducible and attributable to a verifier.

## 3. Non-goals

Version 1 does not define:

- quorum satisfaction;
- weighted voting;
- decision outcome semantics;
- authorization to execute;
- aggregate signatures;
- threshold cryptography;
- a universal public-key infrastructure;
- a transparency log implementation;
- a network transport format;
- a post-quantum algorithm mandate.

These are separate protocol layers.

## 4. Threat model

The protocol assumes an attacker may:

- modify any unsigned JSON field;
- reorder JSON members;
- alter whitespace or encoding;
- replay a signature under another object or protocol;
- claim a different signer or key;
- reuse an old but once-valid key;
- reorder, duplicate, omit, or inject signatures;
- provide malformed UTF-8, duplicate JSON members, decimals, non-finite numbers,
  trailing data, or excessive nesting;
- exploit disagreement between implementations;
- substitute a different Decision Context having similar human meaning;
- publish an object in multiple logs or omit it from a log;
- present a verification receipt created under stale key information.

The protocol does not claim protection against compromise of an authorized private
key while that key is valid. Such compromise is handled through key revocation,
key-history evidence, transparency, and verification policy.

## 5. Core invariants

1. A Decision Context is immutable.
2. Its canonical digest is deterministic.
3. A signature never covers transport metadata.
4. A signature always covers a typed Signature Statement.
5. The Signature Statement binds the context digest, signer, key, algorithm, and
   signing time.
6. The Signed Decision Context may contain multiple independent signatures.
7. Adding or removing a signature does not change the Decision Context digest.
8. Adding or removing a signature does change the Signed Decision Context digest.
9. Signature order is deterministic.
10. Duplicate signature identifiers are forbidden.
11. Duplicate semantic attestations are forbidden.
12. Quorum evaluation is external.
13. Key revocation never erases historical evidence.
14. Verification receipts are evidence of a verification event, not substitutes
    for primary verification.
15. Transparency records are external references, not signature inputs.

## 6. Decision Context digest

For an embedded `agp.decision-context/1` object:

```text
context_bytes =
    AGP-C14N-0.7(decision_context)

context_digest =
    SHA-256(context_bytes)
```

The encoded digest value is lowercase hexadecimal with exactly 64 characters.

The digest algorithm MUST be identified by the registry identifier `sha-256`.

## 7. Signature Statement

Each signature MUST be created over a canonical Signature Statement.

Conceptual structure:

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

The signature input is:

```text
signature_message =
    AGP-C14N-0.7(signature_statement)
```

The signature is:

```text
signature =
    SIGN(
        private_key,
        signature_message,
        algorithm
    )
```

The `purpose` field provides domain separation.

The complete typed statement prevents a valid signature from being reassigned to:

- another protocol;
- another object type;
- another Decision Context;
- another signer;
- another key;
- another algorithm;
- another declared signing time.

## 8. Signed Decision Context object

Conceptual structure:

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
      "signature": "<base64url without padding>"
    }
  ]
}
```

The embedded context is authoritative.

The top-level `context_digest` MUST equal the digest recomputed from the embedded
context.

Every signature statement MUST repeat exactly the same context object type and
digest.

## 9. Signature identifiers

`signature_id` is an audit identifier, not a cryptographic identity.

It MUST:

- be unique within the Signed Decision Context;
- use the common AGP identifier character set;
- remain stable once published;
- not be used as the only replay-prevention mechanism.

Two signatures with different identifiers but identical statement and signature
bytes are duplicates and MUST be rejected.

## 10. Deterministic signature ordering

The `signatures` collection MUST be sorted lexicographically by this tuple:

```text
(
  statement.signer_id,
  statement.key_id,
  statement.algorithm,
  statement.signed_at,
  signature_id
)
```

All comparisons use Unicode scalar-value order over the original string values
accepted by AGP Canonicalization 0.7.

Implementations MUST NOT apply Unicode normalization before comparison.

Implementations MUST reject unsorted collections rather than silently sort them.

## 11. Multi-signature semantics

Version 1 uses independent signatures.

The Signed Decision Context does not state that:

- a quorum was met;
- a signer was authorized;
- a policy was satisfied;
- execution is permitted.

Those conclusions belong to a separate decision or verification layer.

A signer MAY provide multiple signatures for the same context when:

- a key is being rotated;
- classical and post-quantum algorithms are used together;
- multiple attestations are required by policy.

A verifier MUST evaluate each signature independently.

## 12. Duplicate semantic attestations

A Signed Decision Context MUST reject two signature entries with the same tuple:

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

This prevents duplicate entries from being counted twice by downstream systems.

## 13. Key identity and signer identity

`signer_id` identifies the logical authority.

`key_id` identifies one version of cryptographic key material.

They MUST remain separate.

Example:

```text
signer_id = authority:legal
key_id    = key:authority-legal:2026-q3
```

A verifier MUST NOT infer signer identity from a key identifier without trusted
key-history evidence.

## 14. Key resolution

Version 1 does not mandate one key registry.

A verifier may resolve keys from:

- an AGP Key Record;
- an AGP Key Registry;
- a trusted organization directory;
- a transparency log;
- an offline trust bundle;
- another explicitly configured resolver.

The verification receipt MUST record enough resolver evidence to identify the
key material and status used.

## 15. Key lifecycle

A key state model SHOULD support:

- `pending`
- `active`
- `suspended`
- `revoked`
- `retired`

A key-history record SHOULD include:

- signer identifier;
- key identifier;
- algorithm;
- public key;
- validity start;
- validity end;
- revocation time;
- revocation reason;
- superseding key identifier;
- evidence digest.

## 16. Temporal verification

The declared `signed_at` is part of the signed statement but is not self-proving.

A verifier MUST distinguish:

1. cryptographic signature validity;
2. key validity at `signed_at`;
3. key status at verification time;
4. availability of trusted time evidence.

A signature may remain historically valid after a key is retired.

A revoked key may produce one of several policy-dependent outcomes:

- valid before revocation;
- indeterminate because trusted signing time is unavailable;
- invalid because revocation is retroactive;
- invalid because compromise predates the signature.

The receipt MUST expose this distinction rather than collapse it into one boolean.

## 17. Trusted time

Version 1 does not require a trusted timestamp authority.

Possible time evidence includes:

- transparency inclusion time;
- a signed timestamp;
- a trusted system receipt;
- a notarization record;
- a later cryptographic checkpoint.

Without trusted time evidence, `signed_at` remains a signer assertion.

## 18. Revocation semantics

Revocation MUST NOT delete or mutate a historical signature object.

Revocation changes the verifier's evaluation.

A revocation record SHOULD identify:

- the key;
- effective time;
- publication time;
- reason;
- whether the revocation is prospective or retroactive;
- supporting evidence digest.

## 19. Algorithm agility

The object MUST reference algorithms by Schema Registry identifier.

Version 1 reference implementations initially support:

```text
ed25519
```

The object schema MUST NOT encode Ed25519-specific key or signature lengths as
universal protocol constraints.

Algorithm-specific validation belongs to the algorithm profile.

## 20. Post-quantum transition

The architecture supports parallel classical and post-quantum attestations.

Example:

```json
{
  "signer_id": "authority:legal",
  "algorithm": "ed25519"
}
```

and:

```json
{
  "signer_id": "authority:legal",
  "algorithm": "ml-dsa-65"
}
```

A future policy may require both.

Version 1 does not define a synthetic hybrid signature identifier. Independent
parallel signatures are preferred because they are easier to audit and migrate.

A future registry entry MAY define a composed hybrid algorithm if its byte format,
verification semantics, and failure model are fully specified.

## 21. Signed object digest

The Signed Decision Context itself may be canonically digested:

```text
signed_context_digest =
    SHA-256(
        AGP-C14N-0.7(signed_decision_context)
    )
```

This digest changes whenever:

- a signature is added;
- a signature is removed;
- signature order changes;
- any signature metadata changes;
- the embedded context changes.

This digest is suitable for transparency records and verification receipts.

## 22. Transparency integration

A transparency record SHOULD reference:

- the Signed Decision Context digest;
- the context digest;
- log identifier;
- sequence or tree position;
- previous record digest or tree-root evidence;
- recorded time;
- inclusion evidence;
- log signature.

A signature does not need to exist in a log to be cryptographically valid.

A policy may require log inclusion before relying on it.

The same Signed Decision Context may be published in multiple logs.

## 23. Audit model

An auditor SHOULD be able to reconstruct:

1. the exact embedded Decision Context;
2. its canonical bytes;
3. its digest;
4. every Signature Statement;
5. every signature input;
6. every resolved public key;
7. key status at the claimed signing time;
8. key status at verification time;
9. registry versions used;
10. algorithm profiles used;
11. transparency evidence;
12. verification receipts;
13. policy conclusions made downstream.

## 24. Verification receipt

A verifier SHOULD emit:

```json
{
  "object_type": "agp.signature-verification-receipt/1",
  "receipt_id": "receipt:example:0001",
  "signed_context_digest": {
    "algorithm": "sha-256",
    "value": "<64 lowercase hexadecimal characters>"
  },
  "context_digest": {
    "algorithm": "sha-256",
    "value": "<64 lowercase hexadecimal characters>"
  },
  "verified_at": "2026-07-22T20:10:00Z",
  "verifier": {
    "implementation": "agp-reference-python",
    "version": "1.0"
  },
  "registry": {
    "version": "0.8",
    "digest": "<64 lowercase hexadecimal characters>"
  },
  "results": [
    {
      "signature_id": "sig:authority-legal:0001",
      "cryptographic_status": "valid",
      "identity_status": "valid",
      "key_status_at_signing": "active",
      "key_status_at_verification": "retired",
      "time_status": "asserted",
      "overall_status": "valid"
    }
  ],
  "overall_status": "valid"
}
```

## 25. Receipt status model

Recommended values:

### Cryptographic status

- `valid`
- `invalid`
- `unsupported`
- `malformed`

### Identity status

- `valid`
- `mismatch`
- `unresolved`

### Key status at signing

- `active`
- `pending`
- `suspended`
- `revoked`
- `retired`
- `unknown`

### Time status

- `trusted`
- `transparency-bounded`
- `asserted`
- `unavailable`

### Overall status

- `valid`
- `invalid`
- `indeterminate`
- `unsupported`

A receipt MUST preserve component outcomes.

## 26. Error codes

Structural errors:

- `INVALID_JSON`
- `UNKNOWN_TOP_LEVEL_MEMBER`
- `INVALID_OBJECT_TYPE`
- `INVALID_CONTEXT`
- `INVALID_CONTEXT_DIGEST`
- `CONTEXT_DIGEST_MISMATCH`
- `INVALID_SIGNATURE_COLLECTION`
- `EMPTY_SIGNATURE_COLLECTION`
- `UNSORTED_SIGNATURES`
- `DUPLICATE_SIGNATURE_ID`
- `DUPLICATE_ATTESTATION`
- `INVALID_SIGNATURE_STATEMENT`
- `INVALID_SIGNER_ID`
- `INVALID_KEY_ID`
- `INVALID_SIGNATURE_ALGORITHM`
- `INVALID_SIGNED_AT`
- `INVALID_SIGNATURE_ENCODING`

Verification errors:

- `UNSUPPORTED_SIGNATURE_ALGORITHM`
- `KEY_NOT_FOUND`
- `SIGNER_KEY_MISMATCH`
- `KEY_NOT_YET_VALID`
- `KEY_EXPIRED`
- `KEY_SUSPENDED`
- `KEY_REVOKED`
- `INVALID_SIGNATURE`
- `UNTRUSTED_SIGNING_TIME`
- `REGISTRY_REFERENCE_INVALID`
- `KEY_EVIDENCE_INVALID`

## 27. Parser and canonicalization requirements

Implementations MUST reject:

- duplicate JSON members;
- UTF-8 BOM;
- invalid UTF-8;
- trailing non-whitespace data;
- decimal numbers;
- exponent notation;
- non-finite numbers;
- unsafe integers;
- excessive nesting;
- oversized input according to implementation profile.

Implementations MUST use AGP Canonicalization 0.7 for all digests and signature
messages.

## 28. Verification algorithm

A conforming verifier performs, in order:

1. Parse the Signed Decision Context under AGP JSON restrictions.
2. Validate its structural schema.
3. Validate the embedded Decision Context.
4. Canonicalize the embedded Decision Context.
5. Recompute the context digest.
6. Compare it with the top-level context digest.
7. Verify signature ordering and uniqueness.
8. For each signature:
   1. validate the Signature Statement;
   2. verify that its context type and digest match the object;
   3. resolve the algorithm profile;
   4. resolve the key;
   5. verify signer-to-key binding;
   6. canonicalize the Signature Statement;
   7. decode the signature;
   8. verify cryptographically;
   9. evaluate key state and time evidence;
   10. produce a component result.
9. Canonicalize and digest the complete Signed Decision Context.
10. Produce a verification receipt.
11. Apply external policy only after primary verification completes.

## 29. Security consequences of embedding the context

Version 1 embeds the complete Decision Context.

Advantages:

- self-contained verification;
- no ambiguous content retrieval;
- no mutable external reference;
- easier archival;
- deterministic cross-language testing.

Tradeoff:

- larger objects when the context is large.

A future detached profile may reference a context digest only, but it MUST define
content retrieval and availability rules separately.

## 30. Compatibility rule

The historical AGP 0.6 Signed Envelope model is not the signature input for this
object.

An implementation MAY provide an explicit compatibility adapter, but MUST NOT
silently reinterpret an AGP 0.6 envelope as an `agp.signed-decision-context/1`
object.

## 31. Resolved design decisions

Version 1 adopts the following normative design decisions:

1. A Signed Decision Context MUST contain at least one signature.
2. Every signature entry MUST contain an explicit `signature_id`.
3. Every signature entry MUST embed its complete Signature Statement.
4. Signature bytes MUST use unpadded base64url encoding.
5. Every Signature Statement MUST contain `signed_at`.
6. `signed_at` remains signer-asserted unless supported by external trusted-time
   evidence.
7. Public keys and key-history records remain external to the core Signed Decision
   Context object.
8. Verification receipts are independent protocol objects.
9. Verification receipts MUST identify the registry version and registry digest
   used during verification.
10. Maximum input size, nesting depth, signature count, and algorithm-specific
    limits are defined by the applicable conformance profile.
11. Transparency evidence remains external and refers to the canonical digest of
    the complete Signed Decision Context.
12. Version 1 uses independent signatures and does not define aggregate or
    threshold signatures.
13. Parallel classical and post-quantum signatures are represented as separate
    signature entries.
14. Quorum, authorization, decision outcome, and permission to execute remain
    external policy conclusions.
15. Unicode normalization MUST NOT be applied implicitly during signature
    ordering, canonicalization, or verification.

## 32. Version 1 architecture freeze

The following object boundaries are frozen for the first implementation:

```text
agp.decision-context/1
        |
        | canonicalize + digest
        v
agp.signature-statement/1
        |
        | sign independently
        v
agp.signed-decision-context/1
        |
        +--> agp.signature-verification-receipt/1
        |
        +--> agp.transparency-record/1
```

The Signed Decision Context:

- embeds one complete Decision Context;
- repeats its verified digest at the top level;
- contains one or more independently verifiable signature entries;
- does not embed policy conclusions;
- does not embed mutable key state;
- does not embed transparency position;
- does not depend on a transport envelope.

Any future detached-context, aggregate-signature, threshold-signature, or
transport-envelope profile requires a separate object identifier or an explicitly
versioned profile. It MUST NOT silently change the semantics of version 1.

## 33. Planned implementation stages

### Stage 1

- finalize normative Signed Decision Context specification;
- define JSON Schema;
- implement Python structural validator;
- create ephemeral conformance cases.

### Stage 2

- implement Ed25519 verification;
- add Go validator;
- add persistent vectors;
- establish Python/Go parity.

### Stage 3

- define Key Record and key lifecycle evidence;
- add verification receipts;
- test rotation and revocation.

### Stage 4

- add transparency record references;
- add post-quantum algorithm registry entries;
- test hybrid policy scenarios.

### Stage 5

- add CI;
- activate `agp.signed-decision-context/1`;
- open the pull request.

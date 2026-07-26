# DC-3-001: Context-Attested Evidence Provenance

- **Status:** Draft
- **Target object:** `agp.decision-context/3`
- **Companion objects:** `agp.signature-statement/3`,
  `agp.signed-decision-context/3`
- **Intended TPE consumer:** TPE 2.6
- **Compatibility:** additive versioning; Decision Context 1 and 2 remain unchanged

## 1. Abstract

This RFC defines a third generation of the AGP Decision Context evidence
manifest. Decision Context 3 extends each evidence declaration with a canonical,
versioned evidence classification and a declared issuer identity.

The added metadata is covered by the canonical Decision Context digest and by
all signatures over that digest. It is therefore **context-attested provenance**:
the signers of the Decision Context attest that the declared evidence metadata
is the metadata used for the decision.

This RFC does not claim that the evidence issuer independently signed the
evidence or that AGP verified an external issuer credential. Independent
evidence-origin authentication is explicitly outside this RFC.

## 2. Motivation

Decision Context 1 and 2 evidence entries contain exactly:

```json
{
  "id": "evidence:security-review:001",
  "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "media_type": "application/json"
}
```

This permits deterministic requirements over evidence identity, digest,
media type, and count. It does not permit a policy to distinguish:

- a security review from an invoice;
- evidence declared as originating from one authority from evidence declared as
  originating from another;
- multiple evidence items declared as coming from independent issuers.

Adding provenance only inside the Trust Primitive Engine would be incorrect:
the TPE must evaluate immutable, signed input rather than invent unsigned
metadata. The provenance fields therefore belong in a new Decision Context
generation.

## 3. Terminology

### 3.1 Evidence declaration

An entry in the Decision Context `evidence` array that binds a canonical
identifier to a SHA-256 digest, media type, evidence type, and declared issuer.

### 3.2 Evidence type

A canonical, versioned identifier describing the semantic class of an evidence
item, for example:

```text
agp.evidence.security-review/1
```

### 3.3 Declared issuer

The identifier stored in `issuer_id`. It names the authority that the Decision
Context signers declare to be the issuer of the evidence.

### 3.4 Context-attested provenance

Provenance metadata included in the canonical Decision Context digest and
attested by signatures over that digest.

Context-attested provenance is not equivalent to an issuer-origin signature.

## 4. Versioning model

This RFC introduces the coordinated object generation:

```text
agp.decision-context/3
agp.signature-statement/3
agp.signed-decision-context/3
```

The generation mapping is exact:

| Decision Context | Signature Statement | Signed Decision Context |
|---|---|---|
| `agp.decision-context/1` | `agp.signature-statement/1` | `agp.signed-decision-context/1` |
| `agp.decision-context/2` | `agp.signature-statement/2` | `agp.signed-decision-context/2` |
| `agp.decision-context/3` | `agp.signature-statement/3` | `agp.signed-decision-context/3` |

A generation-2 signed envelope MUST NOT wrap a generation-3 Decision Context.

Decision Context 1 and 2 schemas, validators, canonical bytes, digests, vectors,
and behavior MUST remain unchanged.

## 5. Decision Context 3 structure

Decision Context 3 retains every top-level member and semantic rule of Decision
Context 2, including `evaluation_time`.

The only structural change in this RFC is the evidence-entry shape.

### 5.1 Evidence entry

Each entry in `evidence` MUST contain exactly:

```json
{
  "id": "evidence:security-review:001",
  "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "media_type": "application/json",
  "evidence_type": "agp.evidence.security-review/1",
  "issuer_id": "authority:security-lab"
}
```

The required members are:

- `id`
- `digest`
- `media_type`
- `evidence_type`
- `issuer_id`

Additional members are forbidden.

### 5.2 `id`

`id` retains the identifier grammar used by Decision Context 2.

It uniquely identifies the declaration inside the evidence manifest.

### 5.3 `digest`

`digest` retains the Decision Context 2 rule:

- exactly 64 lowercase hexadecimal characters;
- interpreted as a SHA-256 digest declaration.

This RFC does not fetch or hash external evidence content during validation.

### 5.4 `media_type`

`media_type` retains the Decision Context 2 lowercase media-type grammar.

No parameters are admitted by this generation.

### 5.5 `evidence_type`

`evidence_type` MUST:

- be a string;
- satisfy the following exact grammar:

  ```text
  ^[a-z0-9][a-z0-9._:/-]{1,123}[a-z0-9]/[1-9][0-9]*$
  ```

- contain no more than 128 characters in total;
- identify a semantic evidence class;
- include an explicit terminal positive decimal version;
- forbid version `0` and leading-zero versions such as `/01`;
- be compared as an exact, case-sensitive string after validation.

Recommended form:

```text
agp.evidence.<class>/<positive-version>
```

Examples:

```text
agp.evidence.security-review/1
agp.evidence.invoice/1
agp.evidence.deployment-attestation/1
```

This RFC does not establish a global registry of evidence types. Deployments
remain responsible for selecting and governing their accepted identifiers.

### 5.6 `issuer_id`

`issuer_id` MUST:

- be a string;
- satisfy the existing AGP identifier grammar;
- identify the issuer declared by the Decision Context signers;
- be compared as an exact, case-sensitive string after validation.

Examples:

```text
authority:security-lab
authority:external-auditor
service:ci:production
```

`issuer_id` MUST NOT be interpreted as proof that the named issuer signed the
evidence.

## 6. Canonical ordering and uniqueness

The `evidence` array retains Decision Context 2 ordering rules:

- entries MUST be sorted in ascending Unicode code-point order by `id`;
- duplicate `id` values are forbidden.

This RFC does not require uniqueness of:

- `digest`;
- `media_type`;
- `evidence_type`;
- `issuer_id`;
- any tuple composed from those fields.

Multiple evidence declarations may intentionally share an issuer or type.

## 7. Validation rules

A Decision Context 3 validator MUST reject:

- an evidence entry missing `evidence_type`;
- an evidence entry missing `issuer_id`;
- an evidence entry with any unknown member;
- an invalid evidence type identifier;
- an invalid issuer identifier;
- an unsorted evidence collection;
- a duplicate evidence `id`;
- any object that violates inherited Decision Context 2 rules.

Recommended error mapping:

| Condition | Error code |
|---|---|
| malformed evidence object or field | `INVALID_EVIDENCE` |
| duplicate evidence identifier | `DUPLICATE_IDENTIFIER` |
| unsorted evidence collection | `UNSORTED_COLLECTION` |
| unsupported context generation | `INVALID_OBJECT_TYPE` |

No new error code is required for schema-shape failures in this RFC.

## 8. Signature binding

The canonical bytes of the complete Decision Context 3 object, including
`evidence_type` and `issuer_id`, are hashed using the existing AGP
canonicalization and digest profiles.

`agp.signature-statement/3` MUST contain:

```json
{
  "object_type": "agp.signature-statement/3",
  "purpose": "decision-context-attestation",
  "context_object_type": "agp.decision-context/3",
  "context_digest": {
    "algorithm": "sha-256",
    "value": "..."
  },
  "signer_id": "authority:legal",
  "key_id": "key:authority-legal:2026-q3",
  "algorithm": "ed25519",
  "signed_at": "2026-07-25T20:00:00Z"
}
```

`agp.signed-decision-context/3` MUST:

- contain an `agp.decision-context/3`;
- contain a matching SHA-256 context digest;
- contain one or more signatures whose statements are
  `agp.signature-statement/3`;
- reject cross-generation context, statement, or envelope combinations.

The existing append-signature behavior remains unchanged except for the new
exact generation mapping.

## 9. Trust semantics

A valid Signed Decision Context 3 establishes that:

1. the Decision Context bytes are canonical and structurally valid;
2. the declared evidence metadata was included in the signed context digest;
3. the verified context signers attested to that complete context;
4. the evidence manifest was not modified after those signatures were created.

It does not establish that:

- the external evidence bytes are available;
- the declared digest matches bytes fetched by the verifier;
- the declared issuer created, controlled, or signed the evidence;
- the issuer identity is globally unique or externally accredited;
- the evidence statement is truthful;
- the evidence remains current or unrevoked.

These distinctions MUST be preserved in specifications, APIs, logs, and user
documentation.

## 10. Intended TPE 2.6 primitives

After Decision Context 3 and its signed generation are implemented and verified,
TPE 2.6 may define deterministic requirements over the signed manifest.

Candidate primitives are:

```text
evidence_issuer_in
evidence_type_in
evidence_distinct_issuers_at_least
```

The TPE RFC MUST define their exact schemas, normalization, evaluation,
observed bindings, failure codes, composition behavior, recursive-reference
behavior, and compatibility rules.

TPE 2.6 MUST NOT interpret `issuer_id` as an independently verified issuer
signature.

## 11. Compatibility

### 11.1 Decision Context compatibility

Decision Context 1 and 2 remain valid and unchanged.

A Decision Context 3 validator may support all three generations through exact
dispatch. Supporting generation 3 MUST NOT alter validation of generation 1 or
2.

### 11.2 Signed-object compatibility

Signed Decision Context 1 and 2 remain valid and unchanged.

Generation-3 support is additive and MUST use exact generation pairing.

### 11.3 TPE compatibility

Existing TPE releases may reject generation-3 signed contexts as unsupported.

A TPE release that adds generation-3 support MUST preserve existing results for
valid generation-1 and generation-2 inputs.

## 12. Limits

Implementations SHOULD retain existing bounded-resource behavior.

This RFC adds no:

- network access;
- external registry resolution;
- certificate-chain validation;
- issuer discovery;
- evidence retrieval;
- recursive evidence graph;
- free-form metadata object;
- regex matching primitive;
- user-defined expression language.

## 13. Security considerations

### 13.1 False provenance claims

A malicious or mistaken Decision Context signer may declare a false
`issuer_id`. Cryptographic verification proves who signed the context, not that
the declared issuer independently authenticated the evidence.

### 13.2 Semantic type confusion

Deployments must govern accepted `evidence_type` identifiers. Two identifiers
that appear similar are distinct unless exactly equal.

### 13.3 Identifier spoofing

Identifiers are exact strings. Implementations must not apply Unicode
normalization, case folding, display-name substitution, or implicit aliases.

### 13.4 Digest substitution

The evidence digest is part of the signed context, but this RFC does not retrieve
or independently hash evidence content. Systems that consume the evidence bytes
must verify the bytes against the declared digest before relying on them.

### 13.5 Signer authority

A valid signature demonstrates control of a configured key. Whether that signer
was authorized to attest evidence provenance remains an integration and policy
decision.

## 14. Deferred work

The following are intentionally deferred:

- independently signed `agp.evidence-attestation/1` objects;
- issuer credential chains;
- issuer revocation and accreditation;
- external evidence-type registries;
- evidence freshness and validity intervals;
- evidence subject and claim semantics;
- content-addressed evidence retrieval;
- delegation between issuers;
- threshold signatures over individual evidence objects.

## 15. Conformance requirements

A conforming implementation must include tests for at least:

1. valid empty evidence manifest;
2. valid single provenance-bearing evidence entry;
3. valid multiple entries sorted by `id`;
4. missing `evidence_type`;
5. missing `issuer_id`;
6. unknown evidence member;
7. invalid evidence type identifier;
8. invalid issuer identifier;
9. duplicate evidence identifier;
10. unsorted evidence manifest;
11. deterministic replay;
12. Python/Go validation parity;
13. generation-3 signature creation;
14. generation-3 signature append;
15. generation-3 signature verification;
16. rejection of context/statement/envelope generation mismatch;
17. preservation of generation-1 bytes and results;
18. preservation of generation-2 bytes and results.

## 16. Implementation sequence

The implementation SHOULD proceed in this order:

1. approve this RFC;
2. add Decision Context 3 schema;
3. add Python and Go Decision Context 3 validation;
4. add Decision Context 3 conformance vectors;
5. add Signature Statement 3 schema;
6. add Signed Decision Context 3 schema;
7. extend Python signing and validation dispatch;
8. extend Go verification dispatch;
9. add signing, append, verification, and cross-language tests;
10. decide registry activation separately;
11. define and approve the TPE 2.6 RFC;
12. implement TPE 2.6 only after signed DC3 inputs are stable.

## 17. Non-goals

This RFC does not:

- change Decision Context 1 or 2;
- activate Decision Context 2 or 3 in the public registry;
- define TPE 2.6 semantics;
- define an evidence transport protocol;
- establish an issuer public-key infrastructure;
- prove the external origin of evidence;
- authorize any business action.

## 18. Resolved design decisions

### 18.1 Evidence type namespace

`evidence_type` MUST satisfy the exact grammar defined in Section 5.5. Its
terminal version is a positive decimal integer without leading zeroes.

The `agp.evidence.<class>/<version>` form is recommended for protocol-defined
types but is not mandatory. This permits private and organization-specific
namespaces without weakening version determinism.

Examples:

```text
agp.evidence.security-review/1
org.example.evidence.penetration-test/2
vendor:scanner:report/1
```

### 18.2 Issuer identity scope

`issuer_id` MAY reference any valid AGP identifier.

It is not restricted to Decision Context participants, context signers, or
configured keyring entries. An evidence issuer may be external to the decision
and may not possess a key known to the context verifier.

Policies and integrations remain responsible for deciding which issuer
identifiers are trusted.

### 18.3 Evidence type registry

Decision Context 3 does not require evidence types to be registered in the AGP
registry.

A later specification may define registered evidence-type objects or
namespaces. Such a registry must not change exact-string interpretation of
already valid Decision Context 3 objects.

### 18.4 Empty evidence manifests

Decision Context 3 preserves the currently valid empty evidence manifest.

An empty array remains valid:

```json
{
  "evidence": []
}
```

Policies that require evidence must express that requirement through the Trust
Primitive Engine rather than through Decision Context structural validation.

### 18.5 Future evidence attestations

A future independently signed evidence-attestation object SHOULD reuse the
field names and semantics of:

```text
evidence_type
issuer_id
```

That future object may add cryptographic issuer binding, validity intervals,
subject identifiers, claims, or revocation information. Reuse of these fields
does not imply that Decision Context 3 itself provides independent issuer
authentication.

## 19. Decision requested

Approve the following architectural boundary:

> Evidence provenance used by trust policy must first exist as canonical,
> signed Decision Context input. Decision Context 3 records context-attested
> evidence type and issuer declarations. Independent issuer authentication is a
> separate future protocol object.

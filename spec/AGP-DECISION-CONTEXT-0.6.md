# AGP Decision Context and Policy Binding 0.6

Status: Draft  
Protocol: Agent Governance Protocol  
Profile version: 0.6  
Last updated: 2026-07-22

## 1. Abstract

This document defines the AGP Decision Context, the cryptographic binding
between a governed proposal and the policy under which it is evaluated.

An AGP authority MUST NOT approve an unbound proposal payload or proposal
root.

An AGP 0.6 authority MUST sign an AGP Signed Envelope whose payload contains a
Decision Context that binds at least:

- the proposal root;
- the policy identifier;
- the policy version;
- the policy digest;
- the authority-set identifier;
- the execution domain;
- the validity interval;
- the AGP protocol profile.

This prevents valid evidence created under one governance policy from being
reused under another policy, authority set, environment, or protocol profile.

## 2. Motivation

A signature over a proposal proves that an authority approved a particular
proposal.

It does not, by itself, prove:

- which policy governed the approval;
- which authority set was eligible;
- which threshold or resolution rule applied;
- whether the approval was intended for production, staging, or another domain;
- which protocol profile and canonicalization rules were used.

Without explicit policy binding, a malicious coordinator may attempt to reuse
valid evidence under a different policy or decision environment.

This class of attack is called policy substitution.

## 3. Terminology

### 3.1 Proposal

The bounded action or decision submitted for governance.

### 3.2 Proposal Root

The cryptographic digest of the canonical proposal representation.

Field name:

```text
proposal_root
```

### 3.3 Policy

The complete governance rule set used to evaluate evidence.

A policy may define:

- eligible authorities;
- authority roles;
- approval threshold;
- veto rules;
- conflict handling;
- expiration behavior;
- execution constraints;
- required evidence;
- finality rules.

### 3.4 Policy Identifier

A stable human- and machine-readable identifier for a policy family.

Field name:

```text
policy_id
```

Example:

```text
agp.example.deployment-approval
```

A policy identifier alone MUST NOT be treated as sufficient proof of policy
content.

### 3.5 Policy Version

A monotonically managed version label within a policy family.

Field name:

```text
policy_version
```

Example:

```text
3
```

Two policies with the same identifier but different versions MUST be treated as
distinct policies.

### 3.6 Policy Digest

The cryptographic digest of the canonical policy representation.

Field name:

```text
policy_digest
```

The policy digest is the authoritative cryptographic binding to policy content.

### 3.7 Authority Set

The complete set of authorities eligible under the policy.

### 3.8 Authority-Set Identifier

A stable identifier for a particular authority-set configuration.

Field name:

```text
authority_set_id
```

The authority-set identifier SHOULD be content-addressed or otherwise bound to
a canonical authority-set digest.

### 3.9 Execution Domain

The environment or operational scope for which the decision is valid.

Field name:

```text
execution_domain
```

Examples:

```text
production
staging
tenant:example-corp
cluster:payments-prod
repository:agpprotocol/agp
```

Evidence valid for one execution domain MUST NOT be reusable in another domain.

### 3.10 Decision Context

The canonical object that binds the proposal, policy, authority set, execution
domain, validity window, and protocol profile.

### 3.11 Decision Root

The cryptographic digest of the canonical Decision Context.

Field name:

```text
decision_root
```

The Decision Root is a deterministic identifier of the Decision Context.

AGP authorities sign the canonical AGP Signed Envelope containing the Decision
Context, excluding only the envelope's `signature` field.

## 4. Normative envelope and Decision Context

A conforming AGP 0.6 approval MUST use an AGP Signed Envelope compatible with
the AGP 0.4 signed-envelope structure.

The envelope MUST contain:

```json
{
  "envelope_id": "urn:agp:env:<identifier>",
  "object_type": "decision",
  "issuer": "<authority identifier>",
  "key_id": "<signing key identifier>",
  "issued_at": "<RFC3339 timestamp>",
  "expires_at": "<RFC3339 timestamp>",
  "nonce": "<envelope nonce>",
  "payload": {
    "decision_context": {
      "agp_profile": "AGP-0.6",
      "context_type": "agp-decision-context",
      "proposal_root": "sha256:<hex>",
      "policy_id": "<string>",
      "policy_version": "<string-or-integer>",
      "policy_digest": "sha256:<hex>",
      "authority_set_id": "<string>",
      "execution_domain": "<string>",
      "valid_from": "<RFC3339 timestamp>",
      "valid_until": "<RFC3339 timestamp>",
      "decision_nonce": "<globally unique string>"
    }
  },
  "signature": "<base64 Ed25519 signature>"
}
```

The `decision_context` object is the governed object bound to the policy.

The envelope fields remain governed by the signed-envelope profile. The
Decision Context fields remain governed by this specification.

A profile MAY define additional payload fields.

Unknown non-critical fields MAY be preserved.

Unknown critical fields MUST cause deterministic rejection.

## 5. Mandatory field semantics

### 5.1 `agp_profile`

Identifies the exact AGP profile and its canonicalization and verification
rules.

The value MUST be covered by the Decision Root.

A verifier MUST reject unsupported profiles.

### 5.2 `context_type`

Provides domain separation from other signed AGP objects.

For this specification the value MUST be:

```text
agp-decision-context
```

A verifier MUST reject any other value unless another supported specification
defines it.

### 5.3 `proposal_root`

MUST be derived from the canonical governed proposal.

Any governed proposal-field modification MUST change the proposal root.

### 5.4 `policy_id`

MUST identify the intended policy family.

It MUST be non-empty and MUST NOT contain leading or trailing whitespace.

### 5.5 `policy_version`

MUST identify the exact declared policy version.

The version MUST be covered by the Decision Root.

A verifier MUST NOT silently substitute another version.

### 5.6 `policy_digest`

MUST identify the exact canonical policy content.

The digest algorithm MUST be explicitly identified.

AGP 0.6 requires:

```text
sha256:<lowercase hexadecimal digest>
```

A verifier MUST recompute the digest of the supplied policy and compare it with
this field.

### 5.7 `authority_set_id`

MUST identify the authority set applicable to the decision.

A verifier MUST obtain the authority set through an authenticated mechanism.

If the authority set cannot be obtained, verification MUST fail closed.

### 5.8 `execution_domain`

MUST bind evidence to a specific operational environment.

An empty execution domain is invalid.

A generic value such as `default` MAY be used only when explicitly defined by
the policy.

### 5.9 `valid_from`

Defines the earliest instant at which evidence may be considered valid.

### 5.10 `valid_until`

Defines the latest instant at which evidence may be considered valid.

The validity interval MUST satisfy:

```text
valid_from < valid_until
```

The trusted-time assumptions remain profile-dependent.

### 5.11 `decision_nonce`

MUST uniquely identify the decision instance.

It MUST NOT be reused with another Decision Context.

The nonce does not replace proposal, policy, or domain binding.

## 6. Policy canonicalization

A policy MUST be converted to a deterministic canonical byte representation
before computing `policy_digest`.

Until AGP publishes a dedicated canonicalization specification, AGP 0.6 uses
the same canonical JSON rules as the current AGP conformance profile.

At minimum:

- UTF-8 encoding;
- deterministic object-key ordering;
- no insignificant whitespace;
- duplicate JSON keys rejected;
- unsupported numeric forms rejected;
- timestamps normalized according to the profile;
- unknown critical fields rejected.

Two semantically equivalent but byte-different policy inputs MUST produce the
same canonical representation only when the normative canonicalization rules
explicitly define them as equivalent.

## 7. Policy digest computation

Conceptually:

```text
canonical_policy = canonicalize(policy)
policy_digest = "sha256:" + SHA256(canonical_policy)
```

The digest prefix is part of the field value.

A verifier MUST reject:

- missing digest algorithm;
- uppercase or malformed hexadecimal encoding;
- unsupported digest algorithms;
- digest length mismatch;
- policy-content mismatch.

## 8. Decision root computation

Conceptually:

```text
canonical_context = canonicalize(decision_context)
decision_root = "sha256:" + SHA256(canonical_context)
```

The Decision Context MUST NOT include the `decision_root` field while computing
the Decision Root.

The following fields MUST influence the Decision Root:

- `agp_profile`;
- `context_type`;
- `proposal_root`;
- `policy_id`;
- `policy_version`;
- `policy_digest`;
- `authority_set_id`;
- `execution_domain`;
- `valid_from`;
- `valid_until`;
- `decision_nonce`.

Changing any mandatory field MUST change the Decision Root.

## 9. Signature binding

AGP 0.6 preserves the AGP 0.4 signed-envelope model.

The signature input MUST be the canonical JSON representation of the complete
AGP Signed Envelope excluding only the top-level `signature` field.

Conceptually:

```text
signable_envelope = envelope without top-level "signature"
signature_message = canonicalize(signable_envelope)
signature = Ed25519.sign(private_key, signature_message)
```

Because the Decision Context is contained inside `payload`, the signature binds:

- the Decision Context;
- the proposal root;
- the policy identity, version, and digest;
- the authority-set identifier;
- the execution domain;
- the Decision Context validity interval;
- the Decision Context nonce;
- the envelope identity;
- the signer identity and key identifier;
- the envelope issue and expiration times;
- the envelope nonce;
- the envelope object type.

The Decision Root MUST NOT replace the signed envelope as the signature input in
the AGP 0.6 compatibility profile.

The Decision Root MAY be used as:

- a deterministic decision identifier;
- a verification-receipt field;
- a transparency-log reference;
- a cross-language conformance value.

An authority MUST NOT sign:

- only the raw proposal;
- only the proposal root;
- only the Decision Root while claiming AGP 0.6 envelope compatibility;
- only the policy identifier;
- a coordinator-supplied approval count;
- a non-canonical envelope.

## 10. Verification procedure

A conforming verifier MUST perform the following steps:

1. Parse the Decision Context using strict parsing.
2. Reject duplicate or malformed critical fields.
3. Verify that `agp_profile` is supported.
4. Verify that `context_type` is supported.
5. Validate all mandatory field formats.
6. Obtain the governed proposal.
7. Recompute `proposal_root`.
8. Compare the computed proposal root with the declared value.
9. Obtain the policy identified by `policy_id` and `policy_version`.
10. Canonicalize the policy.
11. Recompute `policy_digest`.
12. Compare the computed policy digest with the declared value.
13. Obtain and authenticate the authority set.
14. Verify that the authority set matches `authority_set_id`.
15. Validate `execution_domain`.
16. Validate the Decision Context validity interval.
17. Recompute `decision_root`.
18. Reconstruct the canonical signed envelope excluding `signature`.
19. Verify every authority signature over that canonical envelope.
20. Apply the exact bound policy to the verified evidence.
21. Produce a deterministic verification receipt.

A verifier MUST NOT apply a locally preferred policy when it differs from the
policy bound by the Decision Context.

## 11. Required failure states

A conforming implementation MUST distinguish at least:

- `POLICY_UNAVAILABLE`
- `POLICY_VERSION_MISMATCH`
- `POLICY_DIGEST_MISMATCH`
- `AUTHORITY_SET_UNAVAILABLE`
- `AUTHORITY_SET_MISMATCH`
- `EXECUTION_DOMAIN_MISMATCH`
- `PROPOSAL_ROOT_MISMATCH`
- `DECISION_ROOT_MISMATCH`
- `UNSUPPORTED_PROFILE`
- `INVALID_DECISION_CONTEXT`

These states MUST NOT be silently converted to `REJECTED`.

## 12. Policy substitution attack

Authorities approve proposal `P` under `Policy-A`. A malicious coordinator then
attempts to reuse the same evidence under `Policy-B`, whose authorities,
thresholds, or resolution rules differ.

The verifier MUST return a deterministic policy- or root-mismatch result and
MUST NOT return `APPROVED`.

## 13. Cross-domain replay attack

Evidence approved for `staging` and submitted for `production` MUST produce:

```text
EXECUTION_DOMAIN_MISMATCH
```

or another deterministic invalid-evidence result defined by the profile.

The verifier MUST NOT return `APPROVED`.

## 14. Authority-set substitution attack

Evidence collected under one authority set and evaluated under another authority
set MUST produce `AUTHORITY_SET_MISMATCH` or `DECISION_ROOT_MISMATCH`.

The verifier MUST NOT return `APPROVED`.

## 15. Version and digest semantics

`policy_version` is useful for human interpretation, discovery, migration, and
operations.

`policy_digest` is authoritative for exact content binding and detection of
silent policy changes.

A matching version with a mismatching digest MUST fail.

A matching digest with a differently declared version MUST also fail unless the
profile explicitly defines version aliases.

AGP 0.6 defines no version aliases.

## 16. Policy changes

Any change to a governed policy field MUST produce:

- a new policy version;
- a new policy digest.

This includes changes to authorities, thresholds, veto rules, validity rules,
execution constraints, evidence requirements, conflict semantics, and finality
semantics.

## 17. Receipt requirements

A verification receipt for AGP 0.6 SHOULD include:

```json
{
  "agp_profile": "AGP-0.6",
  "proposal_root": "sha256:<hex>",
  "policy_id": "<string>",
  "policy_version": "<value>",
  "policy_digest": "sha256:<hex>",
  "authority_set_id": "<string>",
  "execution_domain": "<string>",
  "decision_nonce": "<string>",
  "decision_root": "sha256:<hex>",
  "result": "<result-code>"
}
```

The receipt MUST permit an independent verifier to reconstruct the Decision
Root.

## 18. Backward compatibility

Evidence created under earlier AGP profiles does not automatically satisfy AGP
0.6 policy-binding requirements.

A verifier MAY continue supporting earlier profiles, but it MUST clearly identify
evidence lacking policy binding.

Such evidence MUST NOT be presented as AGP 0.6 conformant.

A compatibility result MAY use:

```text
LEGACY_UNBOUND_EVIDENCE
```

## 19. Conformance vectors

AGP 0.6 MUST include positive and negative vectors covering at least:

1. Valid Decision Context.
2. Valid policy digest.
3. Modified policy content.
4. Modified policy version.
5. Modified policy identifier.
6. Modified authority-set identifier.
7. Modified execution domain.
8. Modified validity interval.
9. Modified decision nonce.
10. Reused signature from another policy.
11. Reused signature from another domain.
12. Unknown policy.
13. Unsupported profile.
14. Duplicate critical JSON field.
15. Python and Go byte-identical Decision Roots.
16. Python and Go byte-identical verification receipts.

## 20. Security considerations

Policy binding prevents evidence reuse across policy contexts only when policies
and authority sets are authentic, canonicalization is deterministic, signatures
cover the Decision Root, and verifiers enforce every mandatory binding.

It does not prove that a policy is safe, that authorities make good decisions,
or that an executor follows the receipt.

## 21. Implementation milestones

1. Define canonical policy schema.
2. Implement policy canonicalization.
3. Implement `policy_digest`.
4. Implement Decision Context parsing.
5. Implement `decision_root`.
6. Bind Ed25519 signatures to `decision_root`.
7. Implement failure states.
8. Add Python implementation.
9. Add Go implementation.
10. Add cross-language vectors.
11. Add policy-substitution vectors.
12. Add execution-domain replay vectors.
13. Update verification receipts.
14. Update the full conformance runner.
15. Update documentation and examples.

## 22. Open questions

1. Whether `authority_set_id` should always be a content digest.
2. The authoritative policy-discovery mechanism.
3. Whether policies may import other policies.
4. Whether non-governed descriptive metadata is permitted.
5. Trusted-time requirements for policy activation.
6. Policy revocation semantics.
7. Policy supersession semantics.
8. Privacy-preserving policy and authority-set disclosure.
9. Post-quantum signature profiles.
10. Formal policy-language semantics.

## 23. Review questions

Reviewers are invited to challenge whether every security-relevant field is
bound, whether version and digest semantics are sufficiently strict, whether the
execution-domain model is adequate, and whether policy discovery introduces a
hidden trusted coordinator.

## 24. Normative summary

An AGP 0.6 authority signs a canonical AGP Signed Envelope whose payload
contains a Decision Context.

The Decision Context and its Decision Root bind:

```text
proposal
+ policy
+ authority set
+ execution domain
+ validity interval
+ protocol profile
+ decision nonce
```

Because the Decision Context is contained in the signed payload, a conforming
verifier MUST reject any attempt to modify or substitute one of those
components without obtaining new signatures.

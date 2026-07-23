# AGP Trust Policy 1.0

Status: Draft  
Object identifier: `agp.trust-policy/1`  
Evaluation result identifier: `agp.trust-policy-evaluation/1`  
Canonicalization: `agp-c14n/0.7`  
Digest: `sha-256`

## 1. Scope

This specification defines deterministic trust-policy evaluation over cryptographically verified attestations attached to an AGP Signed Decision Context.

A Trust Policy answers one bounded question:

> Does the set of independently verified signer identities satisfy the trust conditions bound to this Decision Context?

Trust Policy 1.0 defines policy binding by identifier, version, and digest; signer eligibility by participant role; mandatory signers; one-of signer requirements; minimum distinct signer count; minimum combined participant weight; deterministic output; and deterministic failure ordering.

It does not define signature validity, key lifecycle, voting semantics, business rules, execution authorization, evidence truth, transport, storage, or transparency-log inclusion.

## 2. Normative language

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are normative requirements.

## 3. Architectural boundary

Trust Policy Evaluation occurs after structural and cryptographic verification and before a governance resolver or executor.

```text
Decision Context
      |
Signed Decision Context
      |
Signature Verification
      |
Trust Policy Evaluation
      |
Governance Resolver
      |
Authorized Executor
```

A satisfied Trust Policy MUST NOT by itself be interpreted as proposal approval or execution authorization.

## 4. Real-world applicability

### 4.1 Production deployment

A deployment may require operations, either security or compliance, at least two independent authorities, and a minimum combined weight. This prevents one developer, automated system, or compromised authority from acting alone.

### 4.2 High-value payment

A payment may require finance, either legal or risk, a minimum number of distinct authorities, and a minimum combined weight. Amount, destination, currency, and transaction identifier belong in the Decision Context.

### 4.3 Privileged-access change

Independent attestations may be required before granting administrator privileges, changing production credentials, modifying access-control policy, disabling monitoring, or rotating a trust root.

### 4.4 Destructive autonomous-agent action

An autonomous agent may propose deletion, infrastructure termination, account suspension, publication of sensitive information, or production changes. A separate executor must validate the context, freshness, trust result, and its own rules.

### 4.5 Separation of duties

Multiple valid keys belonging to the same signer identity MUST count as one signer. This permits key rotation and multiple devices without allowing one authority to simulate several independent approvals.

## 5. Trust Policy object

A Trust Policy has exactly these members:

- `object_type`
- `policy_id`
- `version`
- `eligible_roles`
- `required_signers`
- `any_of_signers`
- `minimum_signatures`
- `minimum_weight`

Unknown members MUST be rejected.

```json
{
  "object_type": "agp.trust-policy/1",
  "policy_id": "policy:production-change",
  "version": 1,
  "eligible_roles": ["approver", "reviewer"],
  "required_signers": ["authority:operations"],
  "any_of_signers": ["authority:compliance", "authority:security"],
  "minimum_signatures": 2,
  "minimum_weight": 3
}
```

## 6. Identifier syntax

`policy_id` and signer identifiers MUST match:

```text
^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$
```

Identifiers are compared byte-for-byte.

## 7. object_type

`object_type` MUST equal `agp.trust-policy/1`.

## 8. policy_id

`policy_id` identifies a stable policy family. It MUST satisfy the identifier syntax. It MUST NOT be treated as proof of policy content; content identity is provided by the canonical digest.

## 9. version

`version` MUST be an integer from 1 through 9007199254740991 inclusive. A semantic change to trust requirements MUST use a new version. Implementations MUST verify the digest and MUST NOT rely only on identifier and version.

## 10. eligible_roles

`eligible_roles` MUST be a non-empty lexicographically sorted array without duplicates. Allowed values are `approver`, `observer`, `proposer`, `reviewer`, and `voter`.

A verified signer counts only when its `signer_id` is present in Decision Context participants and that participant's role appears in `eligible_roles`.

A verified signer absent from participants is unauthorized and MUST NOT count. A participant whose role is not eligible MUST NOT count.

## 11. required_signers

`required_signers` MUST be a lexicographically sorted array without duplicates and MAY be empty. Every listed identifier MUST appear among matched signer identities.

A required signer that is verified but absent from participants, or assigned an ineligible role, remains missing.

## 12. any_of_signers

`any_of_signers` MUST be a lexicographically sorted array without duplicates and MAY be empty. When non-empty, at least one listed identifier MUST be matched. When empty, this condition is automatically satisfied.

Version 1 defines one flat any-of group. Nested Boolean expressions and multiple independent any-of groups are outside this version.

## 13. minimum_signatures

`minimum_signatures` MUST be an integer from 0 through 9007199254740991 inclusive. It specifies the minimum number of distinct matched signer identities.

Multiple verified signatures from the same `signer_id` MUST count once, regardless of key count, device count, repeated attestations, or key rotation.

## 14. minimum_weight

`minimum_weight` MUST be an integer from 0 through 9007199254740991 inclusive. The evaluator MUST sum the Decision Context participant weight of every distinct matched signer. Each matched signer contributes exactly once.

Weights are defined by the signed Decision Context, not by the Trust Policy.

## 15. Non-empty trust requirement

A policy MUST declare at least one effective trust condition. The following combination is invalid:

```text
required_signers = []
any_of_signers = []
minimum_signatures = 0
minimum_weight = 0
```

`eligible_roles` alone is not sufficient.

## 16. Policy digest and Decision Context binding

The canonical bytes are `AGP-C14N-0.7(trust_policy)`. The digest is SHA-256 over those bytes, encoded as 64 lowercase hexadecimal characters.

The Decision Context reference MUST satisfy:

```text
context.policy.id      == trust_policy.policy_id
context.policy.version == trust_policy.version
context.policy.digest  == SHA-256(AGP-C14N-0.7(trust_policy))
```

Evaluation MUST fail before trust-condition evaluation when any binding does not match.

The Trust Policy does not contain its own digest because that would create a self-referential representation.

## 17. Verified signer derivation

The evaluator MUST select only successfully verified signature entries, derive their `statement.signer_id` values, deduplicate identities, and sort them lexicographically. Unverified signatures MUST NOT participate.

## 18. Matched signer derivation

For each distinct verified signer:

1. Locate the participant with the same identifier.
2. If absent, classify it as unauthorized.
3. Otherwise, if the role is not eligible, classify it as ineligible.
4. Otherwise classify it as matched.

`verified_signers`, `matched_signers`, `unauthorized_signers`, and `ineligible_role_signers` MUST be lexicographically sorted.

## 19. Evaluation semantics

All configured trust conditions use logical AND. A policy is satisfied only when every required signer is matched, the any-of condition is satisfied, the distinct matched signer count reaches `minimum_signatures`, and combined weight reaches `minimum_weight`.

## 20. Failure codes

Unsatisfied trust conditions produce every applicable code in this order:

1. `REQUIRED_SIGNER_MISSING`
2. `ANY_OF_SIGNERS_NOT_SATISFIED`
3. `MINIMUM_SIGNATURES_NOT_REACHED`
4. `MINIMUM_WEIGHT_NOT_REACHED`

Policy binding errors are evaluation errors:

- `POLICY_ID_MISMATCH`
- `POLICY_VERSION_MISMATCH`
- `POLICY_DIGEST_MISMATCH`

An invalid policy produces `INVALID_TRUST_POLICY`. Structural and cryptographic errors retain their existing codes.

## 21. Evaluation result

A successful operation produces `agp.trust-policy-evaluation/1` and includes policy identity and digest, context identity and digest, verified signature IDs, distinct verified signers, matched signers, unauthorized signers, ineligible-role signers, missing required signers, matching any-of signers, signer count, minimum signer count, combined weight, minimum weight, and ordered failure codes.

`status` MUST be `satisfied` when no trust-condition failure exists and `unsatisfied` otherwise.

The result is not a governance decision receipt and is not execution authorization.

## 22. Reference CLI behavior

The reference CLI uses exit code `0` for satisfied, `2` for valid but unsatisfied, and `1` for validation, verification, binding, or processing errors. Integrations SHOULD consume JSON rather than infer semantics from process text.

## 23. Stable authority identities

Signer identifiers SHOULD represent stable authorities rather than devices or key instances, for example `authority:finance`, `authority:legal`, `authority:operations`, or `authority:security`.

A stable authority may be one person, an organizational role, an HSM-backed service, a quorum system, an authorized agent, or multiple rotating keys. The mechanism is outside Trust Policy 1.0.

## 24. Security considerations

### 24.1 Policy substitution

Identifier and version matching alone do not prevent substitution. Implementations MUST verify the canonical digest.

### 24.2 Participant substitution

Roles and weights come from the signed Decision Context. An implementation MUST NOT substitute another participant list after verification.

### 24.3 Duplicate-key amplification

Counting signature entries would let one authority inflate count and weight. Implementations MUST deduplicate by `signer_id`.

### 24.4 Verified but unauthorized signers

A valid signature proves key possession, not authorization for the context. Participant membership and eligible role checks are REQUIRED.

### 24.5 Weight concentration

A policy using only `minimum_weight` may allow one highly weighted authority to satisfy it. Deployments requiring independence SHOULD also set `minimum_signatures` or explicit signer constraints.

### 24.6 Stale keys and revocation

Trust Policy Evaluation assumes the verifier applied intended key-state rules. Version 1 does not define revocation, historical key validity, or trust-root resolution.

### 24.7 Execution boundary

A satisfied result MUST NOT be treated as proof that the proposal is safe, evidence is true, the decision was approved, the context is unexpired, execution remains permitted, or the action was executed.

## 25. Intentionally excluded from version 1

Version 1 does not include arbitrary Boolean expressions, nested groups, multiple independent any-of clauses, time-of-day rules, geographic restrictions, monetary thresholds inside the policy, resource matching, key lifecycle rules, delegation chains, veto signers, dynamic directories, voting positions, vote approval thresholds, or executor behavior.

Proposal-specific values such as amount, resource, environment, destination, and requested action belong in the Decision Context.

## 26. Conformance requirements

A conforming implementation MUST demonstrate rejection of unknown or missing members, invalid identifiers, unsupported roles, unsorted or duplicate arrays, and policies with no effective condition; binding mismatch detection; enforcement of required signers, any-of signers, minimum count, and minimum weight; exclusion of unauthorized and ineligible signers; deduplication by signer identity; and deterministic output ordering.

## 27. Versioning

`agp.trust-policy/1` defines the wire-format major version. Editorial clarifications MAY update this document without changing the identifier. Changes to object members, validation rules, policy semantics, evaluation ordering, or result semantics require a versioned successor.

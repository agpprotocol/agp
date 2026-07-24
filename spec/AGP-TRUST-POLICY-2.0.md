# AGP Trust Policy 2.0 — Trust Primitive Engine

Status: Draft

## 1. Purpose

AGP Trust Policy 2.0 represents trust requirements as an ordered collection of
deterministic primitives. The Trust Primitive Engine (TPE) evaluates every
primitive against the same normalized set of cryptographically verified,
authorized, role-eligible signer identities.

## 2. Compatibility

Trust Policy 2.0 does not modify or reinterpret Trust Policy 1.0.
Implementations may support both versions concurrently.

## 3. Policy object

A policy contains:

- `object_type`: `agp.trust-policy/2`
- `policy_id`
- `version`
- `eligible_roles`
- `requirements`

Requirements MUST be sorted lexicographically by `requirement_id`.
Requirement identifiers MUST be unique.

## 4. Trust primitives

### 4.1 required_signer

Satisfied when `signer_id` is present in the normalized matched signer set.

### 4.2 signer_threshold

Satisfied when at least `minimum_signatures` distinct matched identities belong
to `signer_ids`.

### 4.3 global_signature_threshold

Satisfied when the total number of distinct matched identities is at least
`minimum_signatures`.

### 4.4 global_weight_threshold

Satisfied when the sum of participant weights for distinct matched identities
is at least `minimum_weight`.

### 4.5 role_threshold

Satisfied when at least `minimum_signatures` distinct matched identities have
the participant role named by `role`.

Only identities already admitted to the normalized matched signer set may
contribute. A valid signature from a participant with another role does not
contribute to this primitive.

### 4.6 role_weight_threshold

Satisfied when the sum of participant weights for distinct matched identities
whose participant role equals `role` is at least `minimum_weight`.

Only matched identities with the required role contribute weight. Signers with
another role contribute zero to this primitive.

### 4.7 prohibited_signer

Satisfied when `signer_id` is absent from the normalized matched signer set.

Unsatisfied when that identity is present, with failure code
`PROHIBITED_SIGNER_PRESENT`.

The primitive is evaluated against identities admitted to the matched signer
set after signature verification, participant lookup, role eligibility, and
identity deduplication.

### 4.8 separation_of_duties

Satisfied when both roles listed in `roles` are represented by at least one
matched signer identity.

`roles` MUST contain exactly two distinct role names in lexicographic order.
Because each participant has one normalized role, satisfying both role
positions necessarily requires distinct participant identities.

Unsatisfied when either required role is absent, with failure code
`SEPARATION_OF_DUTIES_NOT_SATISFIED`.

### 4.9 mutual_exclusion

Satisfied when no more than one identity listed in `signer_ids` appears in the
normalized matched signer set.

`signer_ids` MUST contain exactly two distinct signer identifiers in
lexicographic order.

Unsatisfied when both identities are present simultaneously, with failure code
`MUTUAL_EXCLUSION_VIOLATED`.

### 4.10 any_of_signers

Satisfied when at least one identity listed in `signer_ids` appears in the
normalized matched signer set.

`signer_ids` MUST contain at least two distinct signer identifiers in
lexicographic order.

All matching identities are reported deterministically. Unsatisfied when none
of the listed identities is present, with failure code
`ANY_OF_SIGNERS_MISSING`.

### 4.11 all_of_signers

Satisfied when every identity listed in `signer_ids` appears in the normalized
matched signer set.

`signer_ids` MUST contain at least two distinct signer identifiers in
lexicographic order.

Matched and missing identities are reported deterministically. Unsatisfied when
one or more listed identities is absent, with failure code
`ALL_OF_SIGNERS_NOT_SATISFIED`.

### 4.12 exactly_one_of_signers

Satisfied when exactly one identity listed in `signer_ids` appears in the
normalized matched signer set.

`signer_ids` MUST contain at least two distinct signer identifiers in
lexicographic order.

Unsatisfied when none or more than one of the listed identities is present,
with failure code `EXACTLY_ONE_OF_SIGNERS_NOT_SATISFIED`.

### 4.13 at_most_n_signers

Satisfied when no more than `maximum_matches` identities listed in `signer_ids`
appear in the normalized matched signer set.

`signer_ids` MUST contain at least two distinct signer identifiers in
lexicographic order. `maximum_matches` MUST be an integer from zero through
`len(signer_ids) - 1`.

Unsatisfied when the matched identity count exceeds `maximum_matches`, with
failure code `AT_MOST_N_SIGNERS_EXCEEDED`.

### 4.14 at_least_n_signers

Satisfied when at least `minimum_matches` identities listed in `signer_ids`
appear in the normalized matched signer set.

`signer_ids` MUST contain at least two distinct signer identifiers in
lexicographic order. `minimum_matches` MUST be an integer from one through
`len(signer_ids)`.

Unsatisfied when the matched identity count is below `minimum_matches`, with
failure code `AT_LEAST_N_SIGNERS_NOT_REACHED`.

### 4.15 exactly_n_signers

Satisfied when exactly `exact_matches` identities listed in `signer_ids`
appear in the normalized matched signer set.

`signer_ids` MUST contain at least two distinct signer identifiers in
lexicographic order. `exact_matches` MUST be an integer from one through
`len(signer_ids)`.

Unsatisfied when the matched identity count differs from `exact_matches`, with
failure code `EXACTLY_N_SIGNERS_NOT_SATISFIED`.

## 5. Identity normalization

Multiple valid signatures from the same signer identity count as one identity.
Unknown participants and participants whose roles are not eligible do not
contribute to any primitive.

Signer identifier arrays MUST be lexicographically sorted and MUST NOT contain
duplicates. Cardinality values MUST remain within the bounds defined by their
primitive, including rejection of zero where the primitive requires at least
one match.

Implementations MUST treat JSON booleans as booleans, not as integers. A
boolean supplied for any numeric threshold or cardinality field MUST be
rejected as `INVALID_TRUST_POLICY`.

## 6. Composition

The top-level `requirements` array remains an implicit conjunction: every
top-level requirement must be satisfied for the policy to be satisfied.

Trust Primitive Engine 2.2 adds explicit recursive composition requirements:

- `all_of`: satisfied only when every child is satisfied;
- `any_of`: satisfied when at least one child is satisfied;
- `not`: satisfied only when its single child is unsatisfied.

`all_of` and `any_of` MUST contain at least two child requirements in the
`requirements` member. `not` MUST contain exactly one child requirement in the
singular `requirement` member.

Every `requirement_id` MUST be unique across the complete tree. Children of
`all_of` and `any_of` MUST be ordered lexicographically by `requirement_id`.
The maximum tree depth is 8 and the maximum tree size is 256 nodes.

All structurally valid children MUST be evaluated in canonical order. Boolean
composition MUST NOT short-circuit. This preserves complete evidence,
deterministic replay, and byte-stable results.

Composition results preserve the policy tree through recursive `children`
arrays. Full normative semantics are defined by
`trust_primitive_engine/rfcs/TPE-2.2-001-deterministic-policy-composition.md`.

## 7. Evaluation result

The result object type is `agp.trust-policy-evaluation/2`.

Each requirement yields:

- `requirement_id`
- `type`
- `status`
- `matched_signers`
- `observed`
- `expected`
- `failure_code`
- `children` for composition requirements

Requirement results preserve the recursive policy tree and canonical policy
order. Repeated evaluation of identical inputs MUST produce byte-identical
canonical JSON.

## 8. Failure codes

- `REQUIRED_SIGNER_MISSING`
- `SIGNER_THRESHOLD_NOT_REACHED`
- `GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED`
- `GLOBAL_WEIGHT_THRESHOLD_NOT_REACHED`
- `ROLE_THRESHOLD_NOT_REACHED`
- `ROLE_WEIGHT_THRESHOLD_NOT_REACHED`
- `PROHIBITED_SIGNER_PRESENT`
- `SEPARATION_OF_DUTIES_NOT_SATISFIED`
- `MUTUAL_EXCLUSION_VIOLATED`
- `ANY_OF_SIGNERS_MISSING`
- `ALL_OF_SIGNERS_NOT_SATISFIED`
- `EXACTLY_ONE_OF_SIGNERS_NOT_SATISFIED`
- `AT_MOST_N_SIGNERS_EXCEEDED`
- `AT_LEAST_N_SIGNERS_NOT_REACHED`
- `EXACTLY_N_SIGNERS_NOT_SATISFIED`
- `ALL_OF_NOT_SATISFIED`
- `ANY_OF_NOT_SATISFIED`
- `NOT_NOT_SATISFIED`

Validation and binding errors remain fatal evaluation errors rather than
unsatisfied requirements.

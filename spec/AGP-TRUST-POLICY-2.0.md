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

## 5. Identity normalization

Multiple valid signatures from the same signer identity count as one identity.
Unknown participants and participants whose roles are not eligible do not
contribute to any primitive.

## 6. Composition

Phase 1 uses AND composition. A policy is satisfied only if every requirement
is satisfied.

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

Requirement results preserve policy order, which is deterministic because the
policy requires lexical ordering by `requirement_id`.

## 8. Failure codes

- `REQUIRED_SIGNER_MISSING`
- `SIGNER_THRESHOLD_NOT_REACHED`
- `GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED`
- `GLOBAL_WEIGHT_THRESHOLD_NOT_REACHED`
- `ROLE_THRESHOLD_NOT_REACHED`
- `ROLE_WEIGHT_THRESHOLD_NOT_REACHED`
- `PROHIBITED_SIGNER_PRESENT`
- `SEPARATION_OF_DUTIES_NOT_SATISFIED`

Validation and binding errors remain fatal evaluation errors rather than
unsatisfied requirements.

# AGP Attack Matrix

Status: Draft v0.1  
Protocol status: Experimental  
Last updated: 2026-07-22

## 1. Purpose

This document maps concrete adversarial scenarios to expected AGP behavior,
required evidence, current implementation status, and planned validation.

The matrix is intended to prevent vague security claims and to expose gaps
between the protocol design, the reference implementations, and the public
demonstrations.

## 2. Status labels

- IMPLEMENTED: covered by current reference code and automated tests.
- PARTIAL: some protection exists, but important cases or semantics remain open.
- DEMO-ONLY: illustrated in a public demo but not yet proven through the
  normative implementation.
- PLANNED: specified as intended behavior but not yet implemented.
- OUT-OF-SCOPE: AGP cannot establish this property without an external system.

## 3. Attack matrix

| ID | Attack or failure | Expected AGP result | Required protection | Current status | Validation target |
|---|---|---|---|---|---|
| A-001 | Proposal payload modified after approval | INVALID_EVIDENCE or INPUT_ROOT_MISMATCH | Approval bound to canonical proposal root | IMPLEMENTED | Signed vector and benchmark scenario |
| A-002 | Artifact version changed after approval | INVALID_EVIDENCE | Governed artifact digest covered by signed root | IMPLEMENTED / PROFILE-DEPENDENT | Cross-language governed-root vector |
| A-003 | Approval copied to another proposal | INVALID_EVIDENCE | Proposal identifier, nonce and root binding | IMPLEMENTED | Signed replay vector |
| A-004 | Approval copied to another environment | INVALID_EVIDENCE | Execution-domain binding | PLANNED | Production/staging replay test |
| A-005 | Approval reused under another policy | POLICY_VERSION_MISMATCH | Policy identifier and version binding | PLANNED | Policy substitution test |
| A-006 | Approval reused with another authority set | INVALID_EVIDENCE | Authority-set identifier binding | PLANNED | Authority-set substitution test |
| A-007 | Duplicate approval counted twice | INSUFFICIENT_EVIDENCE or INVALID_EVIDENCE | Unique authority identity per decision | IMPLEMENTED | Duplicate-ballot scenario |
| A-008 | Same authority signs APPROVE and REJECT | CONFLICT | Conflict detection by authority and proposal | PLANNED | Conflicting evidence vector |
| A-009 | Unauthorized key signs approval | INVALID_EVIDENCE | Authenticated authority registry | IMPLEMENTED | Unknown-key and wrong-key vectors |
| A-010 | Signature bytes modified | INVALID_EVIDENCE | Signature verification | IMPLEMENTED | Tampered-signature vector |
| A-011 | Signed content modified | INVALID_EVIDENCE | Signature covers canonical envelope | IMPLEMENTED | Tampered-payload vector |
| A-012 | Unknown critical field inserted | INVALID_EVIDENCE | Strict schema and critical-field handling | PLANNED | Parser test |
| A-013 | Duplicate JSON key used ambiguously | INVALID_EVIDENCE | Duplicate-key rejection | PLANNED | Malformed JSON corpus |
| A-014 | Unicode normalization differs across implementations | INVALID_EVIDENCE or deterministic rejection | Normative Unicode rules | PLANNED | Python/Go Unicode vectors |
| A-015 | Number representation differs | INVALID_EVIDENCE or deterministic rejection | Normative numeric canonicalization | PLANNED | Numeric edge vectors |
| A-016 | Timestamp formatting differs | INVALID_EVIDENCE or deterministic rejection | Normative timestamp format | PARTIAL | Timestamp vectors |
| A-017 | Evidence submitted after expiration | EXPIRED | Signed validity window and verifier time | IMPLEMENTED / TRUSTED-TIME-LIMITED | Expired-envelope vector |
| A-018 | Signer backdates approval | INVALID_EVIDENCE or INSUFFICIENT_EVIDENCE | Trusted timestamp or log inclusion | PLANNED | Backdating scenario |
| A-019 | Key revoked before signing | REVOKED | Authentic revocation state | IMPLEMENTED | Revoked-key vector |
| A-020 | Key revoked after valid historical signing | APPROVED or REVOKED according to profile | Historical validity semantics | PLANNED | Revocation-time vectors |
| A-021 | Coordinator omits a rejection | INSUFFICIENT_EVIDENCE or CONFLICT if discovered | Evidence-completeness semantics | PARTIAL | Omission scenario |
| A-022 | Coordinator omits an approval | INSUFFICIENT_EVIDENCE | Fail-closed threshold evaluation | IMPLEMENTED | Omitted-ballot scenario |
| A-023 | Coordinator presents different evidence to two auditors | Detectable only after view comparison | Transparency or gossip mechanism | PARTIAL | Equivocation experiment |
| A-024 | Events delivered in a different order | Same deterministic result | Order-independent evidence normalization | IMPLEMENTED | Reordered-history scenario and conformance suite |
| A-025 | Evidence replayed after decision completion | INVALID_EVIDENCE or no state change | Decision-instance uniqueness / consumed registry | PARTIAL | Replay-after-finality test |
| A-026 | Unsupported cryptographic algorithm declared | INVALID_EVIDENCE | Algorithm allowlist | PARTIAL | Unsupported-algorithm test |
| A-027 | Algorithm identifier omitted | INVALID_EVIDENCE | Mandatory signed algorithm identifier | PLANNED | Missing-field test |
| A-028 | Algorithm downgrade attempted | INVALID_EVIDENCE | Profile and algorithm binding | PLANNED | Downgrade test |
| A-029 | Policy unavailable to verifier | POLICY_UNAVAILABLE | Policy identifier and retrieval rules | PLANNED | Missing-policy test |
| A-030 | Verifier uses wrong policy version | POLICY_VERSION_MISMATCH | Policy digest/version binding | PLANNED | Wrong-version test |
| A-031 | Different implementations produce different roots | INVALID_EVIDENCE / conformance failure | Normative canonicalization | IMPLEMENTED | 260 byte-identical Python-Go vectors |
| A-032 | Different implementations produce different decision | Conformance failure | Normative resolution semantics | IMPLEMENTED | 260/260 cross-language conformance |
| A-033 | Receipt modified after resolution | INVALID_EVIDENCE | Deterministic signed or content-addressed receipt | IMPLEMENTED / MUTATION-TEST-PENDING | Byte-identical verification and audit receipts |
| A-034 | Receipt omits evidence references | INVALID_EVIDENCE or incomplete receipt | Normative receipt schema | PLANNED | Receipt completeness test |
| A-035 | Coordinator fabricates approval count | INVALID_EVIDENCE | Resolver derives counts from verified evidence | IMPLEMENTED | Resolver and benchmark validation |
| A-036 | Network delays evidence | INSUFFICIENT_EVIDENCE or provisional result | Timeout/finality profile | PLANNED | Delayed-evidence scenario |
| A-037 | Network partition creates divergent views | CONFLICT, provisional, or insufficient evidence | Reconciliation semantics | PLANNED | Partition simulation |
| A-038 | Transparency service equivocates | Detectable when conflicting histories are available | Hash-chain validation; gossip still required for remote split views | PARTIAL | Forked-history vector; gossip pending |
| A-039 | Transparency service unavailable | INSUFFICIENT_EVIDENCE or policy-defined fallback | Availability semantics | PLANNED | Log outage test |
| A-040 | Excessively large proposal causes resource exhaustion | INVALID_EVIDENCE / resource-limit rejection | Size and depth limits | PLANNED | Fuzzing and limits test |
| A-041 | Excessive number of signatures causes CPU exhaustion | Resource-limit rejection | Verification budget | PLANNED | Signature-flood test |
| A-042 | Deeply nested malformed input crashes parser | INVALID_EVIDENCE | Bounded parser depth | PLANNED | Parser fuzzing |
| A-043 | Private key is stolen | Cannot prevent malicious valid signatures until revocation | Revocation and key rotation | PARTIAL | Compromise scenario |
| A-044 | Authorized authority approves a harmful proposal | Potentially APPROVED | Policy and human/agent judgment | OUT-OF-SCOPE | Document limitation |
| A-045 | Executor performs a different action | UNVERIFIABLE_EXECUTION or rejection if observed | Execution-binding enforcement point | PLANNED / OUT-OF-SCOPE | Deployment integration |
| A-046 | Executor performs action without AGP | Not detectable without external observer | Mandatory enforcement point | OUT-OF-SCOPE | Document limitation |
| A-047 | Executor hides action from all observers | Not detectable | External observation | OUT-OF-SCOPE | Document limitation |
| A-048 | Signer claims not to understand proposal | Signature remains attributable | Organizational process | OUT-OF-SCOPE | Document limitation |
| A-049 | Confidential proposal leaks through evidence | Not prevented by core AGP | Encryption and access control | OUT-OF-SCOPE | Privacy profile |
| A-050 | Future cryptographic break | Profile migration required | Algorithm agility | PLANNED | Migration design |

## 4. Priority groups

### Priority 0 — before stronger security claims

The following scenarios should be addressed before describing AGP as robust:

- A-001 proposal modification;
- A-003 cross-proposal replay;
- A-005 policy substitution;
- A-007 duplicate approvals;
- A-008 conflicting responses;
- A-009 unauthorized keys;
- A-013 duplicate JSON keys;
- A-019 revocation;
- A-031 cross-language root equality;
- A-032 cross-language decision equality;
- A-033 receipt tampering.

### Priority 1 — before an integration pilot

- execution-domain binding;
- expiration and trusted-time behavior;
- policy retrieval and versioning;
- network delays and partitions;
- receipt completeness;
- resource limits;
- executor binding.

### Priority 2 — advanced profiles

- transparency-log consistency;
- privacy-preserving evidence;
- post-quantum migration;
- selective authority disclosure;
- provisional versus final decisions.

## 5. Result semantics

The matrix deliberately avoids mapping every failure to REJECTED.

Examples:

- Missing approval evidence should normally produce INSUFFICIENT_EVIDENCE.
- A malformed signature should produce INVALID_EVIDENCE.
- An unavailable policy should produce POLICY_UNAVAILABLE.
- Two valid conflicting responses may produce CONFLICT.
- A valid governance receipt with no trusted execution evidence may produce
  UNVERIFIABLE_EXECUTION.

This distinction is required for accurate audit semantics.

## 6. Validation requirements

Each non-out-of-scope row should eventually map to:

- at least one normative test vector;
- at least one negative test;
- expected Python result;
- expected Go result;
- expected receipt state;
- expected error code;
- a reference to the relevant specification section.

## 7. Current interpretation warning

The status values in this draft are preliminary.

They must be verified against:

- the current Python implementation;
- the current Go implementation;
- conformance suites;
- replay and revocation experiments;
- transparency-log experiments;
- benchmark code.

No IMPLEMENTED label should be considered final until linked to an automated
test in the repository.

## 8. Next engineering milestones

1. Audit current code against Priority 0 rows.
2. Define normative result and error codes.
3. Define policy and authority-set binding.
4. Publish canonical cross-language test vectors.
5. Add signed receipt verification.
6. Add parser fuzzing and malformed-input corpus.
7. Build an Ed25519 deployment demo using the actual implementation.
8. Compare AGP with a hardened workflow baseline.

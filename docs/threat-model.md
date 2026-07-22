# AGP Threat Model

Status: Draft v0.1  
Protocol status: Experimental  
Last updated: 2026-07-22

## 1. Purpose

This document defines the adversaries, trust assumptions, protected assets,
security properties, failure modes, and explicit limitations of the Agent
Governance Protocol (AGP).

AGP is intended to make bounded multi-agent governance decisions deterministic,
cryptographically attributable, and independently auditable.

AGP does not attempt to prove that every real-world action was observed, nor
does it make an untrusted execution environment trustworthy by itself.

## 2. System model

An AGP governance decision involves the following logical roles:

- Proposer: creates a proposal for a bounded action.
- Authority: approves, rejects, or otherwise responds to a proposal.
- Coordinator: transports evidence and may orchestrate the workflow.
- Resolver: evaluates evidence according to a specific policy.
- Executor: performs the approved real-world or digital action.
- Auditor: independently verifies the evidence and resulting receipt.
- Transparency service: optionally records commitments or signed events.

A single implementation may perform multiple roles, but the protocol must not
silently assume that those roles are equally trusted.

## 3. Protected assets

AGP is designed to protect:

- the exact proposal content reviewed by authorities;
- the policy under which the decision was made;
- the identity and authorization status of participating authorities;
- the integrity and uniqueness of approval evidence;
- the deterministic resolution result;
- the auditability of the decision after the fact;
- the ability to distinguish valid rejection from insufficient evidence;
- interoperability between independent implementations.

## 4. Adversaries

### 4.1 Malicious coordinator

The coordinator may:

- modify a proposal after authorities approved it;
- omit approvals or rejections;
- replay old evidence;
- duplicate evidence;
- reorder events;
- substitute another policy;
- present different evidence to different verifiers;
- delay delivery;
- attempt to construct a misleading final receipt.

AGP must not rely on coordinator honesty for decision integrity.

### 4.2 Compromised authority

An authority may:

- sign a malicious proposal;
- sign conflicting responses;
- disclose or lose its private key;
- sign after revocation;
- collude with other authorities;
- deny having signed valid evidence.

AGP can attribute signed behavior but cannot guarantee that an authorized
authority made a wise or honest decision.

### 4.3 Malicious proposer

A proposer may:

- construct ambiguous payloads;
- exploit canonicalization differences;
- reuse identifiers or nonces;
- misrepresent the intended action;
- submit proposals near expiration boundaries;
- attempt cross-environment or cross-policy replay.

### 4.4 Malicious executor

An executor may:

- execute a different action from the approved proposal;
- execute an action without presenting evidence;
- claim execution when none occurred;
- conceal execution from observers;
- execute after expiration or revocation.

AGP can verify evidence presented about an action. Detecting an undisclosed
real-world execution requires an external trusted observation or enforcement
point.

### 4.5 Malicious auditor or resolver

A verifier may:

- use an obsolete policy;
- use an obsolete authority set;
- ignore revocation information;
- implement canonicalization incorrectly;
- selectively omit evidence;
- return a fabricated result.

Independent implementations and reproducible test vectors are required to
reduce this risk.

### 4.6 Network attacker

A network attacker may:

- observe traffic;
- delay or drop messages;
- replay messages;
- partition participants;
- present different views to different nodes;
- attempt downgrade attacks.

Confidentiality is not a primary AGP guarantee unless an external encrypted
transport is used.

## 5. Trust assumptions

AGP currently assumes:

1. Cryptographic primitives used by a conforming profile are secure.
2. Private keys of honest authorities remain secret until compromise.
3. Verifiers possess an authentic policy and authority-set configuration.
4. Canonicalization rules are deterministic and implemented identically.
5. At least the policy-required threshold of eligible authorities behaves
   according to the policy.
6. Evidence required for verification is eventually available to the auditor.
7. Revocation state and policy versions can be obtained from an authentic
   source.
8. If execution integrity is claimed, an enforcement or observation point binds
   the executed action to the approved proposal.

If any of these assumptions is false, AGP may return INVALID_EVIDENCE,
INSUFFICIENT_EVIDENCE, CONFLICT, or UNVERIFIABLE_EXECUTION rather than an
approval.

## 6. Intended security properties

### 6.1 Proposal binding

Every approval must be bound to the exact canonical proposal root.

Changing any governed proposal field after approval must invalidate the binding.

### 6.2 Policy binding

Evidence must be bound to:

- protocol version;
- policy identifier and version;
- authority-set identifier;
- required threshold or resolution rule;
- execution domain or environment;
- validity window;
- proposal root.

A valid approval under one policy must not be reusable under another policy.

### 6.3 Authenticity and attribution

A verifier must be able to determine:

- which key produced an evidence item;
- whether that key was authorized;
- whether the signature is valid;
- whether the authority was eligible at the relevant time.

### 6.4 Replay resistance

Evidence must not be reusable for an unrelated proposal, policy, environment,
or decision instance.

Replay controls may include:

- unique proposal identifiers;
- nonces;
- validity windows;
- domain separation;
- consumed-decision registries where required.

### 6.5 Deterministic resolution

Given the same:

- canonical evidence set;
- policy version;
- authority set;
- revocation state;
- protocol profile;

independent conforming resolvers must produce the same result and receipt.

### 6.6 Evidence completeness signaling

AGP must distinguish between:

- evidence proving approval;
- evidence proving rejection;
- malformed or invalid evidence;
- conflicting evidence;
- evidence that is insufficient to decide;
- execution that cannot be independently verified.

Absence of evidence must not silently become approval.

### 6.7 Audit reproducibility

A third party with the required public data must be able to reproduce the
resolution without trusting the original coordinator.

### 6.8 Fail-closed behavior

Unknown critical fields, unsupported algorithms, unavailable policies, invalid
signatures, and unresolved conflicts must not produce APPROVED.

## 7. Proposed resolution states

A conforming resolver should support at least:

- APPROVED
- REJECTED
- INSUFFICIENT_EVIDENCE
- INVALID_EVIDENCE
- POLICY_UNAVAILABLE
- POLICY_VERSION_MISMATCH
- EXPIRED
- REVOKED
- CONFLICT
- UNVERIFIABLE_EXECUTION

These states are not interchangeable.

For example, INSUFFICIENT_EVIDENCE means that approval could not be proven. It
does not necessarily prove that authorities explicitly rejected the proposal.

## 8. Key compromise and revocation

The protocol must define:

- key identifiers;
- authority eligibility periods;
- revocation effective time;
- replacement keys;
- whether revocation is retroactive;
- how historical signatures are evaluated;
- how conflicting revocation views are handled.

A decision signed before a revocation may remain historically valid only if the
protocol can establish that the signature and relevant timestamp evidence
preceded the effective revocation time.

Wall-clock timestamps supplied only by a signer are not sufficient proof of
signing time.

## 9. Time assumptions

Clock time must not be treated as perfectly synchronized.

Profiles using expiration or revocation time must define:

- accepted clock skew;
- time source assumptions;
- boundary behavior;
- handling of missing trusted time;
- whether secure timestamping or transparency inclusion is required.

A resolver must fail closed when time-dependent validity cannot be established.

## 10. Network partitions and equivocation

During a partition, different participants may observe different evidence.

AGP must not claim global finality solely because one coordinator reports a
decision.

Possible outcomes include:

- insufficient evidence;
- conflict;
- provisional result;
- final result after evidence reconciliation.

If a transparency mechanism is used, its consistency and equivocation
properties must be specified separately.

## 11. Canonicalization threats

Canonicalization differences can cause signatures to validate over semantically
different data or fail across implementations.

The normative specification must define:

- character encoding;
- Unicode handling;
- object-key ordering;
- number representation;
- timestamp representation;
- treatment of duplicate keys;
- unknown fields;
- null and omitted values;
- binary data representation.

Parsers must reject ambiguous encodings and duplicate critical fields.

## 12. Algorithm agility and downgrade resistance

Signed evidence must identify the exact cryptographic algorithm and protocol
profile.

Verifiers must reject:

- unsupported algorithms;
- forbidden legacy algorithms;
- algorithm substitution;
- missing algorithm identifiers;
- downgrade to weaker profiles.

Algorithm identifiers must be covered by the signed content.

## 13. Privacy and metadata

AGP evidence may reveal:

- authority identities;
- organizational structure;
- decision timing;
- proposal content;
- approval patterns.

AGP does not provide confidentiality by default.

Deployments requiring privacy must define:

- encrypted transport;
- encrypted evidence storage;
- selective disclosure;
- retention rules;
- access controls;
- metadata minimization.

## 14. Denial of service

AGP does not prevent denial of service.

Attackers may:

- submit excessive evidence;
- create oversized proposals;
- trigger expensive signature verification;
- withhold required evidence;
- flood transparency services.

Implementations should enforce:

- payload-size limits;
- evidence-count limits;
- algorithm allowlists;
- rate limits;
- verification budgets;
- bounded recursion and parsing depth.

## 15. Explicit non-goals

AGP does not by itself guarantee:

- that authorities make correct decisions;
- that all authorities are honest;
- confidentiality of proposals or evidence;
- availability of participants or logs;
- detection of actions hidden from every observer;
- correctness of external policy semantics;
- security of compromised endpoint devices;
- legal enforceability;
- physical-world execution integrity without an external enforcement point;
- protection against all future cryptographic attacks.

## 16. Guarantee boundaries

AGP can establish:

- what proposal was signed;
- who signed it;
- under what policy evidence was evaluated;
- whether supplied evidence satisfies that policy;
- whether independent resolvers reproduce the same result.

AGP cannot establish, without additional trusted evidence:

- that every relevant event was disclosed;
- that a signer understood the proposal;
- that a real-world action matched the approved action;
- that an external system enforced the receipt;
- that no off-protocol decision occurred.

## 17. Open questions

The following items remain open for specification:

1. Exact canonicalization profile.
2. Normative receipt schema.
3. Trusted-time and timestamping profile.
4. Revocation consistency model.
5. Transparency-log requirements.
6. Conflict-resolution semantics.
7. Provisional versus final decisions.
8. Privacy-preserving authority disclosure.
9. Maximum evidence and payload sizes.
10. Formal policy language and evaluation semantics.
11. Execution-binding interface.
12. Post-quantum migration strategy.

## 18. Validation plan

This threat model should be validated through:

- attack-matrix test cases;
- cross-language conformance vectors;
- malformed-input tests;
- property-based testing;
- parser fuzzing;
- coordinator-equivocation scenarios;
- key compromise and revocation scenarios;
- hardened-workflow comparisons;
- external security review.

## 19. Review request

Reviewers are specifically invited to challenge:

- missing adversaries;
- unrealistic trust assumptions;
- ambiguous security properties;
- states that cannot be determined from available evidence;
- hidden reliance on trusted coordinators;
- canonicalization and replay weaknesses;
- revocation and trusted-time assumptions;
- overlap with existing policy and workflow systems.

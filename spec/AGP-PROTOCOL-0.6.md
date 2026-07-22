# Agent Governance Protocol 0.6

## Consolidated Protocol Architecture and Verification Profile

Status: Draft
Protocol: Agent Governance Protocol
Protocol version: 0.6
Last updated: 2026-07-22

## 1. Purpose

This document defines the consolidated architecture of the Agent Governance
Protocol through version 0.6.

It explains how the following protocol profiles compose:

- AGP 0.3 deterministic governance resolution;
- AGP 0.4 signed envelopes;
- AGP 0.5 transparency logs;
- AGP 0.6 Decision Context and policy binding;
- AGP 0.6 Signed Decision Context verification.

This document is an integration specification. The detailed normative behavior
of each component remains defined by its corresponding profile specification.

## 2. Protocol objective

AGP provides a portable and independently verifiable method for governing
bounded decisions made by multiple authorities.

A conforming AGP system can establish:

1. which proposal was governed;
2. which evidence version was active;
3. which authorities were eligible;
4. which signed governance actions were submitted;
5. which policy and authority set applied;
6. which execution domain was authorized;
7. whether the decision was valid at verification time;
8. how the deterministic result was derived;
9. whether the recorded history was altered;
10. whether independent implementations agree on the receipt.

AGP does not establish that evidence is factually true or that an executor
performed the authorized action.

## 3. Layered architecture

AGP separates five logical layers.

### 3.1 Semantic resolution

The semantic layer evaluates canonical governance inputs. It defines proposals,
authority membership snapshots, ballots, objections, vetoes, revocations,
evidence manifests, quorum, approval thresholds, conflict and tie behavior, and
deterministic resolution receipts.

The AGP 0.3 conformance profile tests this layer independently of transport,
signatures and storage.

Normative reference: `spec/AGP-CONFORMANCE-PROFILE-0.3.md`

### 3.2 Signed envelopes

The signature layer authenticates protocol objects and applies key and envelope
validity rules. It verifies required envelope fields, issuer and key binding,
supported signature algorithm, signature integrity, key validity interval, key
revocation, envelope validity interval, and replay protection.

AGP 0.4 uses Ed25519 in the current experimental profile.

Normative reference: `signed/spec/AGP-SIGNED-CONFORMANCE-0.4.md`

### 3.3 Transparency

The transparency layer records governance events in a deterministic,
append-only, hash-linked history. It detects, within its defined threat model,
modified events, deleted entries, reordered entries, truncated history,
duplicate indexes, replaced hashes, and locally observable forks.

Transparency does not independently guarantee global visibility. Detecting
remote split views requires comparison, witnesses, gossip, or another external
observation mechanism.

Normative reference: `transparency/spec/AGP-TRANSPARENCY-LOG-0.5.md`

### 3.4 Decision Context

The Decision Context binds an approval to the complete environment in which the
approval is valid. It binds at least the AGP profile, proposal root, policy
identifier, policy version, policy digest, authority-set identifier,
authority-set digest, execution domain, validity interval, and decision nonce.

This prevents a valid approval from being reused under another proposal,
policy, authority set, environment, or protocol profile.

Normative reference: `spec/AGP-DECISION-CONTEXT-0.6.md`

### 3.5 Signed Decision Context

The Signed Decision Context profile composes the AGP 0.4 signature layer with
the AGP 0.6 semantic binding layer.

A cryptographically valid envelope is necessary but not sufficient for an
accepted Signed Decision Context. The verifier MUST first authenticate the
envelope and then verify the bound Decision Context.

Reference implementations:

- `decision/signed/python/verify_signed_decision.py`
- `decision/signed/go/cmd/agp-signed-decision/main.go`

## 4. High-level lifecycle

1. The proposer creates a proposal.
2. The coordinator canonicalizes the proposal.
3. Policy and authority-set commitments are created.
4. Authorities receive and inspect the Decision Context.
5. Authorities return Signed Decision Context envelopes.
6. A verifier validates signature, key state, replay state, and time bounds.
7. The verifier validates proposal, policy, authority-set, domain, and time bindings.
8. Verified governance evidence is submitted to the deterministic resolver.
9. The resulting receipt may be appended to the transparency log.
10. An auditor can independently replay all verification steps.

## 5. Required verification order

A conforming Signed Decision Context verifier MUST apply checks in the
following broad order.

### 5.1 Parse the outer input

The verifier parses verification time, expected execution domain, keyring,
replay state, and signed envelope. Malformed outer input MUST fail closed.

### 5.2 Verify the signed-envelope layer

Before interpreting the payload as a Decision Context, the verifier MUST check:

1. required envelope fields;
2. issuer and key lookup;
3. supported algorithm;
4. key revocation state;
5. key validity interval;
6. envelope validity interval;
7. replay token;
8. cryptographic signature.

A failure at this stage MUST prevent semantic acceptance of the payload. A
modified payload that was not re-signed MUST produce a signature failure rather
than a policy-binding failure.

### 5.3 Verify the object type

The envelope object type MUST identify a Decision Context object. The current
experimental value is `decision_context`.

Another object type MUST NOT be interpreted as a Decision Context merely
because its payload has similar fields.

### 5.4 Parse the Decision Context payload

The signed payload contains `proposal`, `policy`, `authority_set`, and
`decision_context`.

The verifier MUST fail closed if the payload cannot be interpreted according to
the selected profile.

### 5.5 Recompute semantic commitments

The verifier recomputes `proposal_root`, `policy_digest`,
`authority_set_digest`, and `decision_root`.

The digests MUST be calculated from deterministic canonical representations.

### 5.6 Verify context bindings

The verifier checks the supported AGP profile, Decision Context type,
proposal-root equality, policy identifier, policy version, policy digest,
authority-set identifier, authority-set digest, execution domain, and validity
interval.

### 5.7 Emit the integrated receipt

The current integrated receipt contains:

- `accepted`
- `authority_set_digest`
- `decision_root`
- `envelope_id`
- `error_codes`
- `execution_domain`
- `issuer`
- `key_id`
- `object_type`
- `payload_digest`
- `policy_digest`
- `proposal_root`
- `replay_token`

## 6. Failure precedence

Failure precedence is security-significant.

### 6.1 Cryptographic failure

When signed bytes are modified without a new valid signature, the verifier
reports `INVALID_SIGNATURE`.

It MUST NOT treat an unauthenticated modified payload as authoritative enough
to report only a policy or authority mismatch.

### 6.2 Authenticated semantic failure

A payload may be cryptographically authentic and still be semantically invalid.
Examples include `POLICY_DIGEST_MISMATCH`, `AUTHORITY_SET_MISMATCH`,
`EXECUTION_DOMAIN_MISMATCH`, and `DECISION_EXPIRED`.

This distinction proves that the signer signed the presented bytes but that
those bytes do not authorize the attempted decision environment.

### 6.3 Wrong protocol object

A validly signed object of another type produces `WRONG_OBJECT_TYPE`.

A valid signature does not grant permission to reinterpret one protocol object
as another.

## 7. Canonicalization

Cross-language interoperability requires deterministic canonicalization.

The current experimental implementations use consistent canonical JSON
behavior across Python and Go:

- UTF-8;
- lexicographically ordered object keys;
- no insignificant whitespace;
- deterministic normalization where the profile defines set semantics;
- SHA-256 digests represented as lowercase hexadecimal prefixed by `sha256:`;
- a final newline in emitted receipt files.

The current prototype demonstrates implementation agreement. A future AGP
canonicalization specification must define behavior for duplicate JSON keys,
Unicode normalization, numeric edge cases, unsupported numeric values, maximum
nesting depth, maximum input size, timestamp lexical form, and unknown critical
fields.

## 8. Authority-set normalization

The current AGP 0.6 reference profile normalizes an authority set by sorting
each member's roles, assigning the profile default weight where applicable,
sorting members by `member_id`, and hashing the canonical normalized
authority-set object.

An authority-set identifier alone is not sufficient to bind authority content.
Both the identifier and digest are verified.

## 9. Time model

The current profile uses verifier-supplied time. The verifier checks key
validity, envelope validity, and Decision Context validity.

The verifier time is not controlled by the signed payload. This prevents a
signer from choosing the time at which its own evidence is evaluated.

The current model assumes the verifier's clock is sufficiently trustworthy.
Trusted timestamping and log inclusion proofs remain separate future work.

## 10. Execution-domain binding

The expected execution domain is a local verifier constraint. Examples include
`development`, `staging`, and `production`.

The signed Decision Context declares the authorized execution domain. The
verifier compares it with the locally expected domain.

A coordinator cannot convert a staging approval into a production approval by
changing only local workflow state.

## 11. Transparency composition

A verification receipt or resolution receipt MAY be appended to an AGP
transparency history.

The log can commit to the signed-envelope digest, payload digest, Decision
Context root, deterministic resolution receipt, and relevant policy and
authority-set commitments.

Transparency proves that a particular commitment appeared at a position in the
observed history. It does not replace signature validation or Decision Context
validation.

Recommended composition:

1. signed envelope;
2. signature verification receipt;
3. Decision Context verification receipt;
4. deterministic resolution receipt;
5. transparency-log entry.

## 12. Conformance

The repository contains independent Python and Go reference implementations.

The consolidated conformance command is `python run_all.py`.

The current experimental suites cover:

| Profile | Vectors |
|---|---:|
| AGP 0.3 deterministic resolution | 260 |
| AGP 0.4 signed envelopes | 10 |
| AGP 0.5 transparency | 8 |
| AGP 0.6 Decision Context | 12 |
| AGP 0.6 Signed Decision Context | 7 |

A profile passes only when all commands complete successfully, the
implementation produces the expected decisions or error codes, and Python and
Go receipts are byte-for-byte identical where the profile requires
cross-language comparison.

Passing these suites establishes agreement for the tested vectors. It does not
establish production security or completeness.

## 13. Security properties demonstrated by the prototype

The current implementation demonstrates, for its tested profile:

- deterministic governance resolution;
- signature verification;
- key validity and revocation checks;
- envelope expiration;
- replay detection;
- transparency-chain verification;
- proposal-root binding;
- policy identifier, version, and digest binding;
- authority-set identifier and digest binding;
- execution-domain binding;
- Decision Context validity intervals;
- distinction between cryptographic and authenticated semantic failures;
- byte-identical Python and Go receipts.

## 14. Explicit limitations

AGP 0.6 does not prove that governed evidence is factually correct, that an
authorized authority made a wise decision, that private keys were not
compromised, that every relevant authority response was globally visible, that
a transparency service did not show isolated users different histories, that an
executor performed the approved action, that an executor did not act without
AGP, availability under denial of service, confidentiality of proposal or
policy contents, or production readiness.

The project is experimental and has not received an independent security audit.

## 15. Compatibility

AGP profiles are cumulative but separable.

AGP 0.6 does not modify the verification semantics of AGP 0.3, 0.4, or 0.5.

An implementation MAY support only a subset of profiles, but it MUST advertise
the supported profile explicitly and MUST NOT silently downgrade an object to a
weaker profile.

A Signed Decision Context object MUST NOT be accepted solely as an ordinary AGP
0.4 envelope when the execution path requires AGP 0.6 policy binding.

## 16. Normative document map

- AGP 0.3: `spec/AGP-CONFORMANCE-PROFILE-0.3.md`
- AGP 0.4: `signed/spec/AGP-SIGNED-CONFORMANCE-0.4.md`
- AGP 0.5: `transparency/spec/AGP-TRANSPARENCY-LOG-0.5.md`
- AGP 0.6: `spec/AGP-DECISION-CONTEXT-0.6.md`
- Consolidated architecture: `spec/AGP-PROTOCOL-0.6.md`

## 17. Reference implementation map

- Core resolver: `python/resolver.py`, `go/cmd/agp-resolver/main.go`
- Signed envelopes: `signed/python/signed.py`, `signed/go/cmd/agp-signed/main.go`
- Transparency: `transparency/python/transparency.py`, `transparency/go/cmd/agp-log/main.go`
- Decision Context: `decision/python/decision.py`, `decision/go/cmd/agp-decision/main.go`
- Signed Decision Context: `decision/signed/python/verify_signed_decision.py`, `decision/signed/go/cmd/agp-signed-decision/main.go`

## 18. Future work

Priority work after AGP 0.6 includes:

1. dedicated canonicalization specification;
2. strict schema and duplicate-key rejection;
3. resource and parser limits;
4. trusted timestamp or inclusion-time semantics;
5. transparency witnesses or gossip;
6. conflicting signed authority-action handling;
7. policy retrieval and unavailability semantics;
8. algorithm agility and downgrade prevention;
9. executor-side enforcement profile;
10. independent security review.

# Phase 6B-1 — Stable Public Go API Contract

Phase 6B-1 freezes the existing public Go facade instead of introducing a redundant evaluation API.

Stable entry points:

- tpe.Evaluate
- tpe.EvaluateSigned
- tpe.ErrorCode
- tpe.NewError
- tpe.WrapError

Stable public data types:

- Policy
- PolicyBinding
- Proposal
- Participant
- Evidence
- Context
- SignatureStatement
- Signature
- EvaluationInput
- Evaluation
- Code
- Error

Evaluate accepts an already verified EvaluationInput. EvaluateSigned verifies a serialized Signed Decision Context and then evaluates its authenticated Decision Context.

An unsatisfied policy is returned as a successful Evaluation with status unsatisfied. Fatal errors are reserved for invalid input, signature verification, policy validation, policy-reference, or execution failures.

No public type exposes an internal package type.

// Package tpe provides the stable public Go API for deterministic Trust Primitive Engine evaluation.
//
// Evaluate accepts an already verified EvaluationInput. EvaluateSigned verifies
// a serialized Signed Decision Context before evaluating its authenticated
// Decision Context.
//
// A policy result with status unsatisfied is a successful evaluation, not a
// fatal Go error. Errors are reserved for invalid input, verification,
// validation, policy-reference, or execution failures.
//
// The public compatibility surface consists of Evaluate, EvaluateSigned, the
// public input and result types, and the stable machine-readable error codes.
package tpe

package temporal

import (
	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/contextvalue"
	"fmt"
)

const (
	TypeTimeWindow = "time_window"
	FailureCode    = "TIME_WINDOW_NOT_SATISFIED"
)

func Evaluate(requirement map[string]any, ctx model.Context) (map[string]any, bool, error) {
	requirementID, err := parser.AsString(requirement["requirement_id"], "requirement_id")
	if err != nil {
		return nil, false, err
	}
	notBefore, err := contextvalue.SafeInteger(requirement["not_before"], "not_before")
	if err != nil {
		return nil, false, err
	}
	notAfter, err := contextvalue.SafeInteger(requirement["not_after"], "not_after")
	if err != nil {
		return nil, false, err
	}
	if notBefore < 0 {
		return nil, false, fmt.Errorf(
			"time_window.not_before must be non-negative",
		)
	}
	if notAfter < 0 {
		return nil, false, fmt.Errorf(
			"time_window.not_after must be non-negative",
		)
	}
	if err := ValidateBounds(notBefore, notAfter); err != nil {
		return nil, false, err
	}

	position := "missing"
	var observedTime any
	if ctx.EvaluationTime != nil {
		observedTime = *ctx.EvaluationTime
		switch {
		case *ctx.EvaluationTime < notBefore:
			position = "before"
		case *ctx.EvaluationTime > notAfter:
			position = "after"
		default:
			position = "inside"
		}
	}

	satisfied := position == "inside"
	status := "unsatisfied"
	if satisfied {
		status = "satisfied"
	}

	result := map[string]any{
		"requirement_id":  requirementID,
		"type":            TypeTimeWindow,
		"status":          status,
		"matched_signers": []string{},
		"observed": map[string]any{
			"evaluation_time": observedTime,
			"position":        position,
		},
		"expected": map[string]any{
			"not_before": notBefore,
			"not_after":  notAfter,
		},
		"failure_code": nil,
	}
	if !satisfied {
		result["failure_code"] = FailureCode
	}
	return result, satisfied, nil
}

// ValidateBounds enforces the canonical non-negative inclusive interval.
func ValidateBounds(notBefore, notAfter int64) error {
	if notBefore < 0 {
		return fmt.Errorf(
			"time_window.not_before must be non-negative",
		)
	}
	if notAfter < 0 {
		return fmt.Errorf(
			"time_window.not_after must be non-negative",
		)
	}
	if notBefore > notAfter {
		return fmt.Errorf(
			"time_window.not_before must be less than or equal to " +
				"time_window.not_after",
		)
	}
	return nil
}

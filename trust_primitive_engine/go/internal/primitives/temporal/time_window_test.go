package temporal

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

func decodeRequirement(t *testing.T, raw string) map[string]any {
	t.Helper()
	var requirement map[string]any
	if err := parser.Decode([]byte(raw), &requirement); err != nil {
		t.Fatalf("decode requirement: %v", err)
	}
	return requirement
}

func int64Pointer(value int64) *int64 { return &value }

func TestEvaluateTimeWindow(t *testing.T) {
	requirement := decodeRequirement(t, `{
        "requirement_id":"requirement:deployment-window",
        "type":"time_window",
        "not_before":100,
        "not_after":200
    }`)

	tests := []struct {
		name      string
		value     *int64
		position  string
		satisfied bool
		failure   any
	}{
		{"missing", nil, "missing", false, FailureCode},
		{"before", int64Pointer(99), "before", false, FailureCode},
		{"lower_boundary", int64Pointer(100), "inside", true, nil},
		{"inside", int64Pointer(150), "inside", true, nil},
		{"upper_boundary", int64Pointer(200), "inside", true, nil},
		{"after", int64Pointer(201), "after", false, FailureCode},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, satisfied, err := Evaluate(
				requirement,
				model.Context{EvaluationTime: test.value},
			)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if satisfied != test.satisfied {
				t.Fatalf("satisfied=%v want=%v", satisfied, test.satisfied)
			}
			observed := result["observed"].(map[string]any)
			if observed["position"] != test.position {
				t.Fatalf("position=%v want=%s", observed["position"], test.position)
			}
			if result["failure_code"] != test.failure {
				t.Fatalf("failure_code=%v want=%v", result["failure_code"], test.failure)
			}
		})
	}
}

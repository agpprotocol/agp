package temporal

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

func decodeInvalidTimeWindow(
	t *testing.T,
	raw string,
) map[string]any {
	t.Helper()

	var requirement map[string]any
	if err := parser.Decode([]byte(raw), &requirement); err != nil {
		t.Fatalf("decode requirement: %v", err)
	}
	return requirement
}

func TestEvaluateRejectsInvalidTimeWindowBounds(t *testing.T) {
	tests := []string{
		`{
			"requirement_id":"requirement:deployment-window",
			"type":"time_window",
			"not_before":-1,
			"not_after":200
		}`,
		`{
			"requirement_id":"requirement:deployment-window",
			"type":"time_window",
			"not_before":100,
			"not_after":-1
		}`,
		`{
			"requirement_id":"requirement:deployment-window",
			"type":"time_window",
			"not_before":201,
			"not_after":200
		}`,
	}

	for index, raw := range tests {
		requirement := decodeInvalidTimeWindow(t, raw)

		if _, _, err := Evaluate(
			requirement,
			model.Context{},
		); err == nil {
			t.Fatalf("invalid bounds %d accepted", index)
		}
	}
}

func TestValidateBoundsAcceptsInclusiveZeroWindow(t *testing.T) {
	if err := ValidateBounds(0, 0); err != nil {
		t.Fatalf("zero-width epoch window rejected: %v", err)
	}
}

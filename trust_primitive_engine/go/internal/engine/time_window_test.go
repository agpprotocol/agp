package engine

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/parser"
)

func decodeTemporalRequirement(t *testing.T, raw string) map[string]any {
	t.Helper()
	var requirement map[string]any
	if err := parser.Decode([]byte(raw), &requirement); err != nil {
		t.Fatalf("decode requirement: %v", err)
	}
	return requirement
}

func TestEvaluateRequirementNodeDispatchesTimeWindow(t *testing.T) {
	evaluationTime := int64(150)
	requirement := decodeTemporalRequirement(t, `{
        "requirement_id":"requirement:deployment-window",
        "type":"time_window",
        "not_before":100,
        "not_after":200
    }`)
	result, err := evaluateRequirementNode(
		requirement,
		nil,
		model.Context{EvaluationTime: &evaluationTime},
		nil,
	)
	if err != nil {
		t.Fatalf("evaluateRequirementNode: %v", err)
	}
	if result["status"] != "satisfied" {
		t.Fatalf("status=%v", result["status"])
	}
}

func TestEvaluateRequirementNodeRejectsInvalidTimeWindows(t *testing.T) {
	cases := []string{
		`{"requirement_id":"requirement:deployment-window","type":"time_window","not_before":true,"not_after":200}`,
		`{"requirement_id":"requirement:deployment-window","type":"time_window","not_before":-1,"not_after":200}`,
		`{"requirement_id":"requirement:deployment-window","type":"time_window","not_before":100,"not_after":9007199254740992}`,
		`{"requirement_id":"requirement:deployment-window","type":"time_window","not_before":201,"not_after":200}`,
	}
	for index, raw := range cases {
		requirement := decodeTemporalRequirement(t, raw)
		if _, err := evaluateRequirementNode(
			requirement,
			nil,
			model.Context{},
			nil,
		); err == nil {
			t.Fatalf("invalid requirement %d accepted", index)
		}
	}
}

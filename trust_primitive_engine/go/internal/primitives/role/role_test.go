package role

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func testContext() model.Context {
	return model.Context{
		Participants: []model.Participant{
			{ID: "authority:a", Role: "approver", Weight: 2},
			{ID: "authority:b", Role: "approver", Weight: 3},
			{ID: "authority:c", Role: "observer", Weight: 9},
		},
	}
}

func TestEvaluateThreshold(t *testing.T) {
	requirement := map[string]any{
		"requirement_id":     "requirement:role-threshold",
		"type":               TypeThreshold,
		"role":               "approver",
		"minimum_signatures": 2,
	}
	result, err := EvaluateThreshold(
		requirement,
		testContext(),
		[]string{"authority:a", "authority:b", "authority:c"},
	)
	if err != nil {
		t.Fatalf("evaluate threshold: %v", err)
	}
	if result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEvaluateThresholdExcludesOtherRoles(t *testing.T) {
	requirement := map[string]any{
		"requirement_id":     "requirement:role-threshold",
		"type":               TypeThreshold,
		"role":               "approver",
		"minimum_signatures": 3,
	}
	result, err := EvaluateThreshold(
		requirement,
		testContext(),
		[]string{"authority:a", "authority:b", "authority:c"},
	)
	if err != nil {
		t.Fatalf("evaluate threshold: %v", err)
	}
	if result["failure_code"] != "ROLE_THRESHOLD_NOT_REACHED" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEvaluateWeightThreshold(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:role-weight",
		"type":           TypeWeightThreshold,
		"role":           "approver",
		"minimum_weight": 5,
	}
	result, err := EvaluateWeightThreshold(
		requirement,
		testContext(),
		[]string{"authority:a", "authority:b", "authority:c"},
	)
	if err != nil {
		t.Fatalf("evaluate weight threshold: %v", err)
	}
	if result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
	observed := result["observed"].(map[string]any)
	if observed["weight"] != 5 {
		t.Fatalf("unexpected observed result: %#v", observed)
	}
}

func TestEvaluateWeightThresholdNotReached(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:role-weight",
		"type":           TypeWeightThreshold,
		"role":           "approver",
		"minimum_weight": 6,
	}
	result, err := EvaluateWeightThreshold(
		requirement,
		testContext(),
		[]string{"authority:a", "authority:b", "authority:c"},
	)
	if err != nil {
		t.Fatalf("evaluate weight threshold: %v", err)
	}
	if result["failure_code"] != "ROLE_WEIGHT_THRESHOLD_NOT_REACHED" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

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

func TestEvaluateGlobalThresholdCountsIdentities(t *testing.T) {
	requirement := map[string]any{
		"requirement_id":     "requirement:global-count",
		"type":               TypeGlobalThreshold,
		"minimum_signatures": 3,
	}
	result, err := EvaluateGlobalThreshold(
		requirement,
		[]string{"authority:a", "authority:b"},
	)
	if err != nil {
		t.Fatalf("evaluate global threshold: %v", err)
	}
	if result["failure_code"] != "GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED" {
		t.Fatalf("unexpected result: %#v", result)
	}
	observed := result["observed"].(map[string]any)
	if observed["signature_count"] != 2 {
		t.Fatalf("unexpected observed: %#v", observed)
	}
}

func TestEvaluateGlobalWeight(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:global-weight",
		"type":           TypeGlobalWeight,
		"minimum_weight": 5,
	}
	result, err := EvaluateGlobalWeight(
		requirement,
		testContext(),
		[]string{"authority:a", "authority:b"},
	)
	if err != nil {
		t.Fatalf("evaluate global weight: %v", err)
	}
	if result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestEvaluateSeparationOfDuties(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:separation",
		"type":           TypeSeparation,
		"roles":          []any{"approver", "reviewer"},
	}
	ctx := model.Context{Participants: []model.Participant{
		{ID: "authority:a", Role: "approver", Weight: 1},
		{ID: "authority:b", Role: "reviewer", Weight: 1},
		{ID: "authority:c", Role: "observer", Weight: 1},
	}}
	result, err := EvaluateSeparationOfDuties(requirement, ctx, []string{"authority:a", "authority:b"})
	if err != nil {
		t.Fatalf("evaluate separation: %v", err)
	}
	if result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
	result, err = EvaluateSeparationOfDuties(requirement, ctx, []string{"authority:a"})
	if err != nil {
		t.Fatalf("evaluate missing role: %v", err)
	}
	if result["failure_code"] != "SEPARATION_OF_DUTIES_NOT_SATISFIED" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

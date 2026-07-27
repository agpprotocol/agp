package signer

import "testing"

func TestEvaluateRequired(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:01",
		"type":           TypeRequired,
		"signer_id":      "authority:legal",
	}

	satisfied, err := EvaluateRequired(
		requirement,
		[]string{"authority:legal"},
	)
	if err != nil {
		t.Fatalf("evaluate satisfied: %v", err)
	}
	if satisfied["status"] != "satisfied" {
		t.Fatalf("unexpected satisfied result: %#v", satisfied)
	}

	unsatisfied, err := EvaluateRequired(requirement, nil)
	if err != nil {
		t.Fatalf("evaluate unsatisfied: %v", err)
	}
	if unsatisfied["failure_code"] != "REQUIRED_SIGNER_MISSING" {
		t.Fatalf("unexpected unsatisfied result: %#v", unsatisfied)
	}
}

func TestEvaluateThreshold(t *testing.T) {
	requirement := map[string]any{
		"requirement_id":     "requirement:01",
		"type":               TypeThreshold,
		"signer_ids":         []any{"authority:a", "authority:b"},
		"minimum_signatures": 2,
	}

	result, err := EvaluateThreshold(
		requirement,
		[]string{"authority:a"},
	)
	if err != nil {
		t.Fatalf("evaluate threshold: %v", err)
	}
	if result["status"] != "unsatisfied" ||
		result["failure_code"] != "SIGNER_THRESHOLD_NOT_REACHED" {
		t.Fatalf("unexpected threshold result: %#v", result)
	}
}

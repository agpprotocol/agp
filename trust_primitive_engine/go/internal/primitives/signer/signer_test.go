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

func TestEvaluateProhibited(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:01",
		"type":           TypeProhibited,
		"signer_id":      "authority:security",
	}

	absent, err := EvaluateProhibited(requirement, nil)
	if err != nil || absent["status"] != "satisfied" {
		t.Fatalf("unexpected absent result: %#v err=%v", absent, err)
	}
	present, err := EvaluateProhibited(
		requirement,
		[]string{"authority:security"},
	)
	if err != nil || present["failure_code"] != "PROHIBITED_SIGNER_PRESENT" {
		t.Fatalf("unexpected present result: %#v err=%v", present, err)
	}
}

func TestEvaluateSignerSets(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:01",
		"signer_ids": []any{
			"authority:legal",
			"authority:security",
		},
	}

	requirement["type"] = TypeAnyOf
	anyResult, err := EvaluateAnyOf(requirement, []string{"authority:legal"})
	if err != nil || anyResult["status"] != "satisfied" {
		t.Fatalf("unexpected any result: %#v err=%v", anyResult, err)
	}

	requirement["type"] = TypeAllOf
	allResult, err := EvaluateAllOf(requirement, []string{"authority:legal"})
	if err != nil || allResult["failure_code"] != "ALL_OF_SIGNERS_NOT_SATISFIED" {
		t.Fatalf("unexpected all result: %#v err=%v", allResult, err)
	}

	requirement["type"] = TypeExactlyOne
	exactResult, err := EvaluateExactlyOne(
		requirement,
		[]string{"authority:legal", "authority:security"},
	)
	if err != nil || exactResult["failure_code"] != "EXACTLY_ONE_OF_SIGNERS_NOT_SATISFIED" {
		t.Fatalf("unexpected exactly-one result: %#v err=%v", exactResult, err)
	}
}

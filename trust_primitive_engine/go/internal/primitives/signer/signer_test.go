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

func TestEvaluateSignerCardinalities(t *testing.T) {
	signerIDs := []any{
		"authority:a",
		"authority:b",
		"authority:c",
	}

	tests := []struct {
		name        string
		requirement map[string]any
		matched     []string
		status      string
		failure     any
	}{
		{
			name: "at least satisfied",
			requirement: map[string]any{
				"requirement_id":  "requirement:at-least",
				"type":            TypeAtLeast,
				"signer_ids":      signerIDs,
				"minimum_matches": 2,
			},
			matched: []string{"authority:a", "authority:b"},
			status:  "satisfied",
		},
		{
			name: "at most exceeded",
			requirement: map[string]any{
				"requirement_id":  "requirement:at-most",
				"type":            TypeAtMost,
				"signer_ids":      signerIDs,
				"maximum_matches": 1,
			},
			matched: []string{"authority:a", "authority:b"},
			status:  "unsatisfied",
			failure: "AT_MOST_N_SIGNERS_EXCEEDED",
		},
		{
			name: "exactly n mismatch",
			requirement: map[string]any{
				"requirement_id": "requirement:exactly",
				"type":           TypeExactlyN,
				"signer_ids":     signerIDs,
				"exact_matches":  2,
			},
			matched: []string{"authority:a"},
			status:  "unsatisfied",
			failure: "EXACTLY_N_SIGNERS_NOT_SATISFIED",
		},
	}

	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			var (
				result map[string]any
				err    error
			)
			switch item.requirement["type"] {
			case TypeAtLeast:
				result, err = EvaluateAtLeast(item.requirement, item.matched)
			case TypeAtMost:
				result, err = EvaluateAtMost(item.requirement, item.matched)
			case TypeExactlyN:
				result, err = EvaluateExactlyN(item.requirement, item.matched)
			}
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result["status"] != item.status ||
				result["failure_code"] != item.failure {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

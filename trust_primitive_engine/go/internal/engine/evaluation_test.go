package engine

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/provenance"
)

func leaf(id string, issuer string) map[string]any {
	return map[string]any{
		"requirement_id": id,
		"type":           provenance.TypeIssuerIn,
		"issuer_ids":     []any{issuer},
	}
}

func testContext() model.Context {
	return model.Context{
		ObjectType: "agp.decision-context/3",
		Evidence: []model.Evidence{
			{
				ID:           "evidence:01",
				EvidenceType: "security:assessment/1",
				IssuerID:     "authority:a",
			},
		},
	}
}

func TestEvaluateRequirementsAllOf(t *testing.T) {
	policy := model.Policy{
		PolicyID: "policy:root",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:00",
				"type":           "all_of",
				"requirements": []any{
					leaf("requirement:01", "authority:a"),
					leaf("requirement:02", "authority:b"),
				},
			},
		},
	}
	results, failures, status, err := EvaluateRequirements(
		policy,
		nil,
		testContext(),
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if status != "unsatisfied" || len(results) != 1 || len(failures) != 2 {
		t.Fatalf(
			"unexpected evaluation: status=%s results=%#v failures=%#v",
			status,
			results,
			failures,
		)
	}
}

func TestEvaluateRequirementsPolicyReference(t *testing.T) {
	child := model.Policy{
		PolicyID:     "policy:child",
		Version:      1,
		Requirements: []map[string]any{leaf("requirement:02", "authority:a")},
	}
	root := model.Policy{
		PolicyID: "policy:root",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           typePolicyRef,
				"policy_id":      child.PolicyID,
				"policy_version": child.Version,
				"policy_digest":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}
	_, failures, status, err := EvaluateRequirements(
		root,
		[]model.Policy{child},
		testContext(),
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if status != "satisfied" || len(failures) != 0 {
		t.Fatalf("unexpected status=%s failures=%#v", status, failures)
	}
}

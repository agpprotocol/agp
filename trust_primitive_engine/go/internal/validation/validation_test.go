package validation

import (
	"encoding/json"
	"testing"
)

func validPolicy() map[string]any {
	return map[string]any{
		"object_type":    "agp.trust-policy/2",
		"policy_id":      "policy:example",
		"version":        json.Number("1"),
		"eligible_roles": []any{"approver"},
		"requirements": []any{
			map[string]any{
				"requirement_id": "requirement:01",
				"type":           "evidence_type_in",
				"evidence_types": []any{"security:assessment/1"},
			},
		},
	}
}

func TestValidatePolicyAcceptsValidPolicy(t *testing.T) {
	if err := ValidatePolicy(validPolicy()); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func TestValidatePolicyRejectsUnsortedRequirements(t *testing.T) {
	policy := validPolicy()
	policy["requirements"] = []any{
		map[string]any{
			"requirement_id": "requirement:02",
			"type":           "evidence_type_in",
			"evidence_types": []any{"security:assessment/1"},
		},
		map[string]any{
			"requirement_id": "requirement:01",
			"type":           "evidence_type_in",
			"evidence_types": []any{"security:assessment/1"},
		},
	}
	if err := ValidatePolicy(policy); err == nil {
		t.Fatal("unsorted requirements accepted")
	}
}

func TestValidateRequirementRejectsNonCanonicalSet(t *testing.T) {
	requirement := map[string]any{
		"requirement_id": "requirement:01",
		"type":           "evidence_issuer_in",
		"issuer_ids":     []any{"authority:b", "authority:a"},
	}
	if err := ValidateRequirement(requirement); err == nil {
		t.Fatal("non-canonical issuer set accepted")
	}
}

func TestValidateRequirementTreeRejectsDuplicateIDs(t *testing.T) {
	raw := []any{
		map[string]any{
			"requirement_id": "requirement:01",
			"type":           "all_of",
			"requirements": []any{
				map[string]any{
					"requirement_id": "requirement:02",
					"type":           "evidence_type_in",
					"evidence_types": []any{"security:assessment/1"},
				},
				map[string]any{
					"requirement_id": "requirement:02",
					"type":           "evidence_type_in",
					"evidence_types": []any{"security:assessment/1"},
				},
			},
		},
	}
	if err := ValidateRequirementTree(raw); err == nil {
		t.Fatal("duplicate requirement ids accepted")
	}
}

func TestValidateSignerRequirements(t *testing.T) {
	validRequired := map[string]any{
		"requirement_id": "requirement:required",
		"type":           "required_signer",
		"signer_id":      "authority:legal",
	}
	if err := ValidateRequirement(validRequired); err != nil {
		t.Fatalf("valid required signer rejected: %v", err)
	}

	validThreshold := map[string]any{
		"requirement_id":     "requirement:threshold",
		"type":               "signer_threshold",
		"signer_ids":         []any{"authority:a", "authority:b"},
		"minimum_signatures": 1,
	}
	if err := ValidateRequirement(validThreshold); err != nil {
		t.Fatalf("valid signer threshold rejected: %v", err)
	}

	invalid := map[string]any{
		"requirement_id":     "requirement:threshold",
		"type":               "signer_threshold",
		"signer_ids":         []any{"authority:b", "authority:a"},
		"minimum_signatures": 1,
	}
	if err := ValidateRequirement(invalid); err == nil {
		t.Fatal("unsorted signer ids accepted")
	}
}

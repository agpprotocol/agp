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

func TestValidateSignerSetRequirements(t *testing.T) {
	for _, primitiveType := range []string{
		"any_of_signers",
		"all_of_signers",
		"exactly_one_of_signers",
	} {
		valid := map[string]any{
			"requirement_id": "requirement:set",
			"type":           primitiveType,
			"signer_ids": []any{
				"authority:legal",
				"authority:security",
			},
		}
		if err := ValidateRequirement(valid); err != nil {
			t.Fatalf("valid %s rejected: %v", primitiveType, err)
		}
	}

	tooShort := map[string]any{
		"requirement_id": "requirement:set",
		"type":           "any_of_signers",
		"signer_ids":     []any{"authority:legal"},
	}
	if err := ValidateRequirement(tooShort); err == nil {
		t.Fatal("one-entry signer set accepted")
	}
}

func TestValidateSignerCardinalities(t *testing.T) {
	valid := []map[string]any{
		{
			"requirement_id": "requirement:at-least",
			"type":           "at_least_n_signers",
			"signer_ids": []any{
				"authority:a",
				"authority:b",
				"authority:c",
			},
			"minimum_matches": 2,
		},
		{
			"requirement_id": "requirement:at-most",
			"type":           "at_most_n_signers",
			"signer_ids": []any{
				"authority:a",
				"authority:b",
				"authority:c",
			},
			"maximum_matches": 1,
		},
		{
			"requirement_id": "requirement:exactly",
			"type":           "exactly_n_signers",
			"signer_ids": []any{
				"authority:a",
				"authority:b",
				"authority:c",
			},
			"exact_matches": 2,
		},
	}

	for _, requirement := range valid {
		if err := ValidateRequirement(requirement); err != nil {
			t.Fatalf(
				"valid %s rejected: %v",
				requirement["type"],
				err,
			)
		}
	}

	invalid := map[string]any{
		"requirement_id": "requirement:at-most",
		"type":           "at_most_n_signers",
		"signer_ids": []any{
			"authority:a",
			"authority:b",
		},
		"maximum_matches": 2,
	}
	if err := ValidateRequirement(invalid); err == nil {
		t.Fatal("non-restrictive at-most limit accepted")
	}
}

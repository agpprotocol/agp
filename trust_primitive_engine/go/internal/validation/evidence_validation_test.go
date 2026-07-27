package validation

import "testing"

func TestValidateEvidencePresentRequirement(t *testing.T) {
	valid := []map[string]any{
		{
			"requirement_id": "requirement:present",
			"type":           "evidence_present",
			"evidence_id":    "evidence:report",
		},
		{
			"requirement_id": "requirement:bound",
			"type":           "evidence_present",
			"evidence_id":    "evidence:report",
			"digest":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"media_type":     "application/json",
		},
	}
	for _, requirement := range valid {
		if err := ValidateRequirement(requirement); err != nil {
			t.Fatalf("valid evidence_present rejected: %v", err)
		}
	}

	invalid := []map[string]any{
		{
			"requirement_id": "requirement:missing-id",
			"type":           "evidence_present",
		},
		{
			"requirement_id": "requirement:bad-digest",
			"type":           "evidence_present",
			"evidence_id":    "evidence:report",
			"digest":         "A",
		},
		{
			"requirement_id": "requirement:bad-media",
			"type":           "evidence_present",
			"evidence_id":    "evidence:report",
			"media_type":     "APPLICATION/JSON",
		},
		{
			"requirement_id": "requirement:unknown",
			"type":           "evidence_present",
			"evidence_id":    "evidence:report",
			"extra":          true,
		},
	}
	for _, requirement := range invalid {
		if err := ValidateRequirement(requirement); err == nil {
			t.Fatalf("invalid evidence_present accepted: %#v", requirement)
		}
	}
}

func TestValidateEvidenceCountRequirement(t *testing.T) {
	valid := []map[string]any{
		{
			"requirement_id": "requirement:count-min",
			"type":           "evidence_count_at_least",
			"minimum":        1,
		},
		{
			"requirement_id": "requirement:count-max",
			"type":           "evidence_count_at_least",
			"minimum":        256,
			"media_type":     "application/pdf",
		},
	}
	for _, requirement := range valid {
		if err := ValidateRequirement(requirement); err != nil {
			t.Fatalf("valid evidence count rejected: %v", err)
		}
	}

	for _, minimum := range []any{false, 0, 257, "2"} {
		requirement := map[string]any{
			"requirement_id": "requirement:bad-count",
			"type":           "evidence_count_at_least",
			"minimum":        minimum,
		}
		if err := ValidateRequirement(requirement); err == nil {
			t.Fatalf("invalid minimum accepted: %#v", minimum)
		}
	}
}

package engine

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func TestEvidenceLeafDispatch(t *testing.T) {
	ctx := model.Context{
		Evidence: []model.Evidence{
			{
				ID:        "evidence:report",
				Digest:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				MediaType: "application/json",
			},
		},
	}

	tests := []struct {
		name        string
		requirement map[string]any
	}{
		{
			name: "present",
			requirement: map[string]any{
				"requirement_id": "requirement:present",
				"type":           "evidence_present",
				"evidence_id":    "evidence:report",
				"digest":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
		{
			name: "count",
			requirement: map[string]any{
				"requirement_id": "requirement:count",
				"type":           "evidence_count_at_least",
				"minimum":        1,
				"media_type":     "application/json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := evaluateRequirementNode(
				test.requirement,
				nil,
				ctx,
				nil,
			)
			if err != nil {
				t.Fatalf("dispatch failed: %v", err)
			}
			if result["status"] != "satisfied" {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

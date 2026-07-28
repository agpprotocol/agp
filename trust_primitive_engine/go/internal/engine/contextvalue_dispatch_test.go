package engine

import (
	"encoding/json"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func TestBasicContextLeafDispatch(t *testing.T) {
	ctx := model.Context{
		Proposal: model.Proposal{
			Payload: map[string]any{
				"environment": "production",
				"coverage":    json.Number("9000"),
				"rollout":     json.Number("2500"),
				"requested":   "3.0.0",
				"approved":    "3.0.0",
			},
		},
	}

	requirements := []map[string]any{
		{
			"requirement_id": "requirement:present",
			"type":           "context_value_present",
			"path":           "/proposal/payload/environment",
		},
		{
			"requirement_id": "requirement:equals",
			"type":           "context_value_equals",
			"path":           "/proposal/payload/environment",
			"value":          "production",
		},
		{
			"requirement_id": "requirement:in",
			"type":           "context_value_in",
			"path":           "/proposal/payload/environment",
			"values":         []any{"production", "staging"},
		},
		{
			"requirement_id": "requirement:path-equals",
			"type":           "context_path_equals",
			"left_path":      "/proposal/payload/requested",
			"right_path":     "/proposal/payload/approved",
		},
		{
			"requirement_id": "requirement:minimum",
			"type":           "context_integer_at_least",
			"path":           "/proposal/payload/coverage",
			"minimum":        json.Number("9000"),
		},
		{
			"requirement_id": "requirement:maximum",
			"type":           "context_integer_at_most",
			"path":           "/proposal/payload/rollout",
			"maximum":        json.Number("2500"),
		},
	}

	for _, requirement := range requirements {
		result, err := evaluateRequirementNode(
			requirement,
			nil,
			ctx,
			nil,
		)
		if err != nil {
			t.Fatalf("%s dispatch failed: %v", requirement["type"], err)
		}
		if result["status"] != "satisfied" {
			t.Fatalf("%s unexpected result: %#v", requirement["type"], result)
		}
	}
}

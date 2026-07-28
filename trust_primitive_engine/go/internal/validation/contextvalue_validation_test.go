package validation

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateBasicContextRequirements(t *testing.T) {
	valid := []map[string]any{
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
			"requirement_id": "requirement:minimum",
			"type":           "context_integer_at_least",
			"path":           "/proposal/payload/coverage",
			"minimum":        json.Number("-9007199254740991"),
		},
		{
			"requirement_id": "requirement:maximum",
			"type":           "context_integer_at_most",
			"path":           "/proposal/payload/rollout",
			"maximum":        json.Number("9007199254740991"),
		},
	}
	for _, requirement := range valid {
		if err := ValidateRequirement(requirement); err != nil {
			t.Fatalf("valid %s rejected: %v", requirement["type"], err)
		}
	}
}

func TestRejectInvalidBasicContextRequirements(t *testing.T) {
	invalid := []map[string]any{
		{
			"requirement_id": "requirement:present",
			"type":           "context_value_present",
			"path":           "/participants/0/id",
		},
		{
			"requirement_id": "requirement:equals",
			"type":           "context_value_equals",
			"path":           "/proposal/payload/object",
			"value":          map[string]any{"name": "service"},
		},
		{
			"requirement_id": "requirement:long",
			"type":           "context_value_equals",
			"path":           "/proposal/payload/environment",
			"value":          strings.Repeat("x", 4097),
		},
		{
			"requirement_id": "requirement:unsafe",
			"type":           "context_value_equals",
			"path":           "/proposal/payload/coverage",
			"value":          json.Number("9007199254740992"),
		},
		{
			"requirement_id": "requirement:boolean",
			"type":           "context_integer_at_least",
			"path":           "/proposal/payload/coverage",
			"minimum":        true,
		},
		{
			"requirement_id": "requirement:decimal",
			"type":           "context_integer_at_most",
			"path":           "/proposal/payload/rollout",
			"maximum":        2500.5,
		},
	}
	for _, requirement := range invalid {
		if err := ValidateRequirement(requirement); err == nil {
			t.Fatalf("invalid requirement accepted: %#v", requirement)
		}
	}
}

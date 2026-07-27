package provenance

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func dc3Context() model.Context {
	return model.Context{
		ObjectType: "agp.decision-context/3",
		Evidence: []model.Evidence{
			{
				ID:           "evidence:01",
				EvidenceType: "security:assessment/1",
				IssuerID:     "authority:a",
			},
			{
				ID:           "evidence:02",
				EvidenceType: "security:assessment/1",
				IssuerID:     "authority:b",
			},
		},
	}
}

func TestEvaluateIssuerIn(t *testing.T) {
	result, failure, err := EvaluateIssuerIn(
		map[string]any{
			"requirement_id": "requirement:01",
			"type":           TypeIssuerIn,
			"issuer_ids":     []any{"authority:a"},
		},
		dc3Context(),
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result["status"] != "satisfied" || failure != "" {
		t.Fatalf("unexpected result: %#v failure=%q", result, failure)
	}
}

func TestEvaluateEvidenceTypeUnavailable(t *testing.T) {
	ctx := dc3Context()
	ctx.ObjectType = "agp.decision-context/2"
	result, failure, err := EvaluateEvidenceTypeIn(
		map[string]any{
			"requirement_id": "requirement:01",
			"type":           TypeEvidenceIn,
			"evidence_types": []any{"security:assessment/1"},
		},
		ctx,
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result["status"] != "unsatisfied" ||
		failure != "EVIDENCE_TYPE_NOT_ALLOWED" {
		t.Fatalf("unexpected result: %#v failure=%q", result, failure)
	}
}

func TestEvaluateDistinctIssuers(t *testing.T) {
	result, failure, err := EvaluateDistinctIssuers(
		map[string]any{
			"requirement_id": "requirement:01",
			"type":           TypeDistinctIssuer,
			"minimum":        2,
		},
		dc3Context(),
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if result["status"] != "satisfied" || failure != "" {
		t.Fatalf("unexpected result: %#v failure=%q", result, failure)
	}
}

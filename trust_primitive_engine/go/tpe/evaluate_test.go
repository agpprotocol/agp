package tpe_test

import (
	"encoding/json"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/tpe"
)

func TestEvaluatePublicAPI(t *testing.T) {
	input := tpe.EvaluationInput{
		ContextDigest: "context-digest",
		Context: tpe.Context{
			ObjectType: "agp.decision-context/3",
			ContextID:  "context:01",
			Policy: tpe.PolicyBinding{
				ID:      "policy:root",
				Version: 1,
				Digest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			Evidence: []tpe.Evidence{
				{
					ID:           "evidence:01",
					EvidenceType: "security:assessment/1",
					IssuerID:     "authority:a",
				},
			},
		},
	}
	root := tpe.Policy{
		ObjectType: "agp.trust-policy/2",
		PolicyID:   "policy:root",
		Version:    1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           "evidence_issuer_in",
				"issuer_ids":     []any{"authority:a"},
			},
		},
	}

	result, err := tpe.Evaluate(input, root, nil)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if result.Status != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.PolicyID != "policy:root" {
		t.Fatalf("unexpected policy id: %q", result.PolicyID)
	}
	if len(result.FailureCodes) != 0 {
		t.Fatalf("unexpected failure codes: %#v", result.FailureCodes)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("empty encoded result")
	}
}

func TestEvaluatePublicAPIUnsatisfiedIsNotFatal(t *testing.T) {
	input := tpe.EvaluationInput{
		Context: tpe.Context{
			ContextID: "context:01",
			Policy: tpe.PolicyBinding{
				ID:      "policy:root",
				Version: 1,
				Digest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}
	root := tpe.Policy{
		PolicyID: "policy:root",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           "evidence_issuer_in",
				"issuer_ids":     []any{"authority:a"},
			},
		},
	}

	result, err := tpe.Evaluate(input, root, nil)
	if err != nil {
		t.Fatalf("unsatisfied evaluation returned fatal error: %v", err)
	}
	if result.Status != "unsatisfied" {
		t.Fatalf("unexpected status: %q", result.Status)
	}
	if len(result.FailureCodes) == 0 {
		t.Fatal("unsatisfied result has no failure codes")
	}
}

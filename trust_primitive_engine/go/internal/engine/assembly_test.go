package engine

import (
	"reflect"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/provenance"
)

func TestSignerProjection(t *testing.T) {
	input := model.EvaluationInput{
		Context: model.Context{
			Participants: []model.Participant{
				{ID: "authority:a", Role: "approver", Weight: 2},
				{ID: "authority:b", Role: "observer", Weight: 4},
			},
		},
		Signatures: []model.Signature{
			{
				SignatureID: "signature:02",
				Statement: model.SignatureStatement{
					SignerID: "authority:b",
				},
			},
			{
				SignatureID: "signature:01",
				Statement: model.SignatureStatement{
					SignerID: "authority:a",
				},
			},
			{
				SignatureID: "signature:03",
				Statement: model.SignatureStatement{
					SignerID: "authority:unknown",
				},
			},
		},
	}
	root := model.Policy{EligibleRoles: []string{"approver"}}

	ids, verified, matched, unauthorized, ineligible, weight :=
		SignerProjection(input, root)

	if !reflect.DeepEqual(
		ids,
		[]string{"signature:01", "signature:02", "signature:03"},
	) {
		t.Fatalf("unexpected signature ids: %#v", ids)
	}
	if !reflect.DeepEqual(
		verified,
		[]string{"authority:a", "authority:b", "authority:unknown"},
	) {
		t.Fatalf("unexpected verified signers: %#v", verified)
	}
	if !reflect.DeepEqual(matched, []string{"authority:a"}) {
		t.Fatalf("unexpected matched signers: %#v", matched)
	}
	if !reflect.DeepEqual(unauthorized, []string{"authority:unknown"}) {
		t.Fatalf("unexpected unauthorized signers: %#v", unauthorized)
	}
	if !reflect.DeepEqual(ineligible, []string{"authority:b"}) {
		t.Fatalf("unexpected ineligible signers: %#v", ineligible)
	}
	if weight != 2 {
		t.Fatalf("unexpected weight: %d", weight)
	}
}

func TestReproduce(t *testing.T) {
	input := model.EvaluationInput{
		ContextDigest: "context-digest",
		Context: model.Context{
			ContextID:  "context:01",
			ObjectType: "agp.decision-context/3",
			Policy: model.PolicyBinding{
				ID:      "policy:root",
				Version: 1,
				Digest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			Evidence: []model.Evidence{
				{
					ID:           "evidence:01",
					EvidenceType: "security:assessment/1",
					IssuerID:     "authority:a",
				},
			},
		},
	}
	root := model.Policy{
		ObjectType:    "agp.trust-policy/2",
		PolicyID:      "policy:root",
		Version:       1,
		EligibleRoles: []string{"approver"},
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           provenance.TypeIssuerIn,
				"issuer_ids":     []any{"authority:a"},
			},
		},
	}

	result, err := Reproduce(input, root, nil)
	if err != nil {
		t.Fatalf("reproduce failed: %v", err)
	}
	if result["status"] != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result["policy_id"] != "policy:root" {
		t.Fatalf("unexpected policy id: %#v", result["policy_id"])
	}
	if result["signature_count"] != 0 {
		t.Fatalf("unexpected signature count: %#v", result["signature_count"])
	}
}

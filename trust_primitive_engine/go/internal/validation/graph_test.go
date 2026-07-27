package validation

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
)

func leafPolicy(id string) model.Policy {
	return model.Policy{
		ObjectType:    "agp.trust-policy/2",
		PolicyID:      id,
		Version:       1,
		EligibleRoles: []string{"approver"},
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           "evidence_type_in",
				"evidence_types": []any{"security:assessment/1"},
			},
		},
	}
}

func referencePolicy(id string, target model.Policy) model.Policy {
	digest, err := compactPolicyDigest(target)
	if err != nil {
		panic(err)
	}
	return model.Policy{
		ObjectType:    "agp.trust-policy/2",
		PolicyID:      id,
		Version:       1,
		EligibleRoles: []string{"approver"},
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           "policy_reference",
				"policy_id":      target.PolicyID,
				"policy_version": target.Version,
				"policy_digest":  digest,
			},
		},
	}
}

func TestValidatePolicyReferenceGraphDirect(t *testing.T) {
	child := leafPolicy("policy:child")
	root := referencePolicy("policy:root", child)
	if err := ValidatePolicyReferenceGraph(
		root,
		[]model.Policy{child},
	); err != nil {
		t.Fatalf("valid graph rejected: %v", err)
	}
}

func TestValidatePolicyReferenceGraphMissingPolicy(t *testing.T) {
	child := leafPolicy("policy:child")
	root := referencePolicy("policy:root", child)
	err := ValidatePolicyReferenceGraph(root, nil)
	if GraphErrorCode(err) != "POLICY_REFERENCE_NOT_FOUND" {
		t.Fatalf("unexpected error: %v code=%s", err, GraphErrorCode(err))
	}
}

func TestValidatePolicyReferenceGraphRejectsDuplicateIdentity(t *testing.T) {
	child := leafPolicy("policy:child")
	err := ValidatePolicyReferenceGraph(
		leafPolicy("policy:root"),
		[]model.Policy{child, child},
	)
	if GraphErrorCode(err) != "INVALID_TRUST_POLICY_SET" {
		t.Fatalf("unexpected error: %v code=%s", err, GraphErrorCode(err))
	}
}

package engine

import (
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/internal/model"
	"agpprotocol.org/agp/trust-primitive-engine/internal/primitives/provenance"
)

func leaf(id string, issuer string) map[string]any {
	return map[string]any{
		"requirement_id": id,
		"type":           provenance.TypeIssuerIn,
		"issuer_ids":     []any{issuer},
	}
}

func testContext() model.Context {
	return model.Context{
		ObjectType: "agp.decision-context/3",
		Evidence: []model.Evidence{
			{
				ID:           "evidence:01",
				EvidenceType: "security:assessment/1",
				IssuerID:     "authority:a",
			},
		},
	}
}

func TestEvaluateRequirementsAllOf(t *testing.T) {
	policy := model.Policy{
		PolicyID: "policy:root",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:00",
				"type":           "all_of",
				"requirements": []any{
					leaf("requirement:01", "authority:a"),
					leaf("requirement:02", "authority:b"),
				},
			},
		},
	}
	results, failures, status, err := EvaluateRequirements(
		policy,
		nil,
		testContext(),
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if status != "unsatisfied" || len(results) != 1 || len(failures) != 2 {
		t.Fatalf(
			"unexpected evaluation: status=%s results=%#v failures=%#v",
			status,
			results,
			failures,
		)
	}
}

func TestEvaluateRequirementsPolicyReference(t *testing.T) {
	child := model.Policy{
		PolicyID:     "policy:child",
		Version:      1,
		Requirements: []map[string]any{leaf("requirement:02", "authority:a")},
	}
	root := model.Policy{
		PolicyID: "policy:root",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           typePolicyRef,
				"policy_id":      child.PolicyID,
				"policy_version": child.Version,
				"policy_digest":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}
	_, failures, status, err := EvaluateRequirements(
		root,
		[]model.Policy{child},
		testContext(),
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if status != "satisfied" || len(failures) != 0 {
		t.Fatalf("unexpected status=%s failures=%#v", status, failures)
	}
}

func TestPolicyReferenceProjectsMatchedSigners(t *testing.T) {
	signerID := "authority:approver-a"

	child := model.Policy{
		PolicyID: "policy:child-signer",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:child-signer",
				"type":           "required_signer",
				"signer_id":      signerID,
			},
		},
	}

	root := model.Policy{
		PolicyID: "policy:root-signer-reference",
		Version:  1,
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:root",
				"type":           "all_of",
				"requirements": []any{
					map[string]any{
						"requirement_id": "requirement:a-reference",
						"type":           typePolicyRef,
						"policy_id":      child.PolicyID,
						"policy_version": child.Version,
						"policy_digest":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
					map[string]any{
						"requirement_id": "requirement:b-signer",
						"type":           "required_signer",
						"signer_id":      signerID,
					},
				},
			},
		},
	}

	results, failures, status, err := evaluateRequirementsWithSigners(
		root,
		[]model.Policy{child},
		model.Context{},
		[]string{signerID},
	)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if status != "satisfied" {
		t.Fatalf("unexpected status: %s", status)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %#v", failures)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected result count: %d", len(results))
	}

	rootResult, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("root result has unexpected type: %T", results[0])
	}

	rootMatched := resultMatchedSigners(rootResult)
	if len(rootMatched) != 1 || rootMatched[0] != signerID {
		t.Fatalf(
			"root matched_signers=%#v, expected %#v",
			rootMatched,
			[]string{signerID},
		)
	}

	children, ok := rootResult["children"].([]any)
	if !ok || len(children) != 2 {
		t.Fatalf("unexpected children: %#v", rootResult["children"])
	}

	referenceResult, ok := children[0].(map[string]any)
	if !ok {
		t.Fatalf(
			"reference result has unexpected type: %T",
			children[0],
		)
	}

	referenceMatched := resultMatchedSigners(referenceResult)
	if len(referenceMatched) != 1 ||
		referenceMatched[0] != signerID {
		t.Fatalf(
			"reference matched_signers=%#v, expected %#v",
			referenceMatched,
			[]string{signerID},
		)
	}
}

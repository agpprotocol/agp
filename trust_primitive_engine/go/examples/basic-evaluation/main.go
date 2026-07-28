package main

import (
	"encoding/json"
	"fmt"
	"log"

	"agpprotocol.org/agp/trust-primitive-engine/tpe"
)

func main() {
	evaluationTime := int64(1700000000)

	input := tpe.EvaluationInput{
		ObjectType:    "agp.signed-decision-context/2",
		ContextDigest: "context-digest:example",
		Context: tpe.Context{
			ObjectType:     "agp.decision-context/3",
			ContextID:      "context:example",
			EvaluationTime: &evaluationTime,
			Policy: tpe.PolicyBinding{
				ID:      "policy:example",
				Version: 1,
				Digest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			Proposal: tpe.Proposal{
				Type: "proposal:deployment",
				Payload: map[string]any{
					"environment": "production",
				},
			},
			Participants: []tpe.Participant{
				{
					ID:     "authority:approver-a",
					Role:   "approver",
					Weight: 1,
				},
			},
			Evidence: []tpe.Evidence{},
		},
		Signatures: []tpe.Signature{
			{
				SignatureID: "signature:01",
				Statement: tpe.SignatureStatement{
					SignerID: "authority:approver-a",
				},
			},
		},
	}

	policy := tpe.Policy{
		ObjectType:    "agp.trust-policy/2",
		PolicyID:      "policy:example",
		Version:       1,
		EligibleRoles: []string{"approver"},
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:approval",
				"type":           "required_signer",
				"signer_id":      "authority:approver-a",
			},
			{
				"requirement_id": "requirement:environment",
				"type":           "context_value_equals",
				"path":           "/proposal/payload/environment",
				"value":          "production",
			},
		},
	}

	result, err := tpe.Evaluate(input, policy, nil)
	if err != nil {
		log.Fatal(err)
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(encoded))
}

package main

import (
	_ "embed"
	"fmt"
	"log"

	"agpprotocol.org/agp/trust-primitive-engine/tpe"
)

//go:embed signed-context.json
var signedContextJSON []byte

//go:embed keyring.json
var keyringJSON []byte

func approvalPolicy() tpe.Policy {
	return tpe.Policy{
		ObjectType:    "agp.trust-policy/2",
		PolicyID:      "policy:example:approval",
		Version:       1,
		EligibleRoles: []string{"approver"},
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:01",
				"type":           "required_signer",
				"signer_id":      "authority:legal",
			},
		},
	}
}

func main() {
	result, err := tpe.EvaluateSigned(
		signedContextJSON,
		keyringJSON,
		approvalPolicy(),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	if result.Status != "satisfied" {
		log.Fatalf("unexpected status: %s", result.Status)
	}

	if len(result.VerifiedSigners) != 1 {
		log.Fatalf(
			"unexpected verified signers: %#v",
			result.VerifiedSigners,
		)
	}

	fmt.Printf(
		"EXTERNAL_TPE_SATISFIED_PASS status=%s signer=%s\n",
		result.Status,
		result.VerifiedSigners[0],
	)
}

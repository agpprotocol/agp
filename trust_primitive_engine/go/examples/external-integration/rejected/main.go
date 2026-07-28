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
	_, err := tpe.EvaluateSigned(
		signedContextJSON,
		keyringJSON,
		approvalPolicy(),
		nil,
	)
	if err == nil {
		log.Fatal("tampered Signed Decision Context was accepted")
	}

	code, ok := tpe.ErrorCode(err)
	if !ok {
		log.Fatalf("error is not typed: %v", err)
	}
	if code != tpe.CodeSignatureVerificationFailed {
		log.Fatalf("unexpected error code: %s", code)
	}

	fmt.Printf(
		"EXTERNAL_TPE_REJECTED_PASS code=%s\n",
		code,
	)
}

package tpe_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"agpprotocol.org/agp/trust-primitive-engine/tpe"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	return filepath.Clean(
		filepath.Join(filepath.Dir(file), "..", "..", ".."),
	)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(
		repositoryRoot(t),
		"signed_decision_context",
		"vectors",
		name,
	))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func signedRootPolicy() tpe.Policy {
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

func TestEvaluateSignedValidVector(t *testing.T) {
	result, err := tpe.EvaluateSigned(
		readFixture(t, "001_valid_ed25519_signature.input.json"),
		readFixture(t, "001_valid_ed25519_signature.keyring.json"),
		signedRootPolicy(),
		nil,
	)
	if err != nil {
		t.Fatalf("evaluate signed: %v", err)
	}
	if result.Status != "satisfied" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.VerifiedSigners) != 1 ||
		result.VerifiedSigners[0] != "authority:legal" {
		t.Fatalf(
			"unexpected verified signers: %#v",
			result.VerifiedSigners,
		)
	}
}

func TestEvaluateSignedTamperedVector(t *testing.T) {
	_, err := tpe.EvaluateSigned(
		readFixture(t, "002_tampered_signature.input.json"),
		readFixture(t, "002_tampered_signature.keyring.json"),
		signedRootPolicy(),
		nil,
	)
	if err == nil {
		t.Fatal("tampered signed context unexpectedly evaluated")
	}
	code, ok := tpe.ErrorCode(err)
	if !ok || code != tpe.CodeSignatureVerificationFailed {
		t.Fatalf("unexpected error: code=%q err=%v", code, err)
	}
}

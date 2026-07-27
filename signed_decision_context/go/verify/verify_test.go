package verify_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestVerifyValidVector(t *testing.T) {
	root := moduleRoot(t)
	value, err := verifyapi.LoadJSON(filepath.Join(
		root,
		"vectors",
		"001_valid_ed25519_signature.input.json",
	))
	if err != nil {
		t.Fatalf("load input: %v", err)
	}
	keyring, err := verifyapi.LoadKeyring(filepath.Join(
		root,
		"vectors",
		"001_valid_ed25519_signature.keyring.json",
	))
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}

	result, err := verifyapi.Verify(value, keyring)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result["status"] != "verified" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestVerifyTamperedVector(t *testing.T) {
	root := moduleRoot(t)
	value, err := verifyapi.LoadJSON(filepath.Join(
		root,
		"vectors",
		"002_tampered_signature.input.json",
	))
	if err != nil {
		t.Fatalf("load input: %v", err)
	}
	keyring, err := verifyapi.LoadKeyring(filepath.Join(
		root,
		"vectors",
		"002_tampered_signature.keyring.json",
	))
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}

	_, err = verifyapi.Verify(value, keyring)
	if err == nil {
		t.Fatal("tampered vector unexpectedly verified")
	}
	status, code, _, ok := verifyapi.FailureDetails(err)
	if !ok {
		t.Fatalf("unexpected error type: %T", err)
	}
	if status != "unverified" ||
		code != "SIGNATURE_VERIFICATION_FAILED" {
		t.Fatalf("unexpected failure: status=%q code=%q", status, code)
	}
}

func TestParseKeyringAndVerifyTyped(t *testing.T) {
	root := moduleRoot(t)

	inputRaw, err := os.ReadFile(filepath.Join(
		root,
		"vectors",
		"001_valid_ed25519_signature.input.json",
	))
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	keyringRaw, err := os.ReadFile(filepath.Join(
		root,
		"vectors",
		"001_valid_ed25519_signature.keyring.json",
	))
	if err != nil {
		t.Fatalf("read keyring: %v", err)
	}

	value, err := verifyapi.ParseJSON(inputRaw)
	if err != nil {
		t.Fatalf("parse input: %v", err)
	}
	keyring, err := verifyapi.ParseKeyring(keyringRaw)
	if err != nil {
		t.Fatalf("parse keyring: %v", err)
	}

	result, err := verifyapi.VerifyTyped(value, keyring)
	if err != nil {
		t.Fatalf("verify typed: %v", err)
	}
	if result.Status != "verified" {
		t.Fatalf("unexpected status: %q", result.Status)
	}
	if result.VerifiedSignatureCount != 1 {
		t.Fatalf(
			"unexpected verified signature count: %d",
			result.VerifiedSignatureCount,
		)
	}
	if len(result.VerifiedSignatureIDs) != 1 {
		t.Fatalf(
			"unexpected verified ids: %#v",
			result.VerifiedSignatureIDs,
		)
	}
}

func TestParseKeyringRejectsInvalidJSON(t *testing.T) {
	_, err := verifyapi.ParseKeyring([]byte(`{"keys":[`))
	if err == nil {
		t.Fatal("invalid keyring unexpectedly parsed")
	}
	status, code, _, ok := verifyapi.FailureDetails(err)
	if !ok {
		t.Fatalf("unexpected error type: %T", err)
	}
	if status != "unverified" || code != "INVALID_KEYRING" {
		t.Fatalf("unexpected failure: status=%q code=%q", status, code)
	}
}

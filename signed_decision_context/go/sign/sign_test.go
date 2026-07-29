package sign_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"agpprotocol.org/agp/signed-decision-context/sign"
	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

func privateKey(t *testing.T, seedStart byte) ed25519.PrivateKey {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = seedStart + byte(index)
	}

	raw := []byte(
		`{"algorithm":"ed25519","private_key":"` +
			base64.RawURLEncoding.EncodeToString(seed) +
			`"}`,
	)

	key, err := sign.ParsePrivateKey(raw)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	return key
}

func contextV1() map[string]any {
	return map[string]any{
		"object_type": "agp.decision-context/1",
		"context_id":  "ctx:sign:test:001",
		"created_at":  "2026-07-28T20:00:00Z",
		"expires_at":  nil,
		"policy": map[string]any{
			"id":      "policy:example:approval",
			"version": int64(1),
			"digest":  "1111111111111111111111111111111111111111111111111111111111111111",
		},
		"proposal": map[string]any{
			"type": "proposal:example:change",
			"payload": map[string]any{
				"enabled": true,
			},
		},
		"participants": []any{
			map[string]any{
				"id":     "authority:legal",
				"role":   "approver",
				"weight": int64(1),
			},
		},
		"evidence":    []any{},
		"constraints": []any{},
	}
}

func TestCreateProducesStructurallyValidSignedContext(t *testing.T) {
	result, err := sign.Create(
		contextV1(),
		privateKey(t, 1),
		sign.Options{
			SignerID:    "authority:legal",
			KeyID:       "key:legal:2026-q3",
			SignatureID: "sig:legal:0002",
			SignedAt:    "2026-07-28T20:00:00Z",
		},
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	structural, err := verifyapi.StructuralValidate(result)
	if err != nil {
		t.Fatalf("structural validate: %v", err)
	}

	if structural.ObjectType != "agp.signed-decision-context/1" {
		t.Fatalf("unexpected object type: %s", structural.ObjectType)
	}
	if structural.SignatureCount != 1 {
		t.Fatalf(
			"unexpected signature count: %d",
			structural.SignatureCount,
		)
	}
}

func TestCreateIsDeterministic(t *testing.T) {
	options := sign.Options{
		SignerID:    "authority:legal",
		KeyID:       "key:legal:2026-q3",
		SignatureID: "sig:legal:0002",
		SignedAt:    "2026-07-28T20:00:00Z",
	}

	first, err := sign.Create(
		contextV1(),
		privateKey(t, 1),
		options,
	)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	second, err := sign.Create(
		contextV1(),
		privateKey(t, 1),
		options,
	)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}

	firstBytes, err := sign.CanonicalBytes(first)
	if err != nil {
		t.Fatalf("first canonical bytes: %v", err)
	}

	secondBytes, err := sign.CanonicalBytes(second)
	if err != nil {
		t.Fatalf("second canonical bytes: %v", err)
	}

	if string(firstBytes) != string(secondBytes) {
		t.Fatal("deterministic create produced different bytes")
	}
}

func TestAppendSortsAndPreservesExistingSignature(t *testing.T) {
	first, err := sign.Create(
		contextV1(),
		privateKey(t, 1),
		sign.Options{
			SignerID:    "authority:legal",
			KeyID:       "key:legal:2026-q3",
			SignatureID: "sig:legal:0002",
			SignedAt:    "2026-07-28T20:00:00Z",
		},
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	firstBytes, err := sign.CanonicalBytes(first["signatures"].([]any)[0])
	if err != nil {
		t.Fatalf("canonical existing signature: %v", err)
	}

	second, err := sign.Append(
		first,
		privateKey(t, 33),
		sign.Options{
			SignerID:    "authority:finance",
			KeyID:       "key:finance:2026-q3",
			SignatureID: "sig:finance:0001",
			SignedAt:    "2026-07-28T20:01:00Z",
		},
	)
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	signatures := second["signatures"].([]any)
	if len(signatures) != 2 {
		t.Fatalf("unexpected signature count: %d", len(signatures))
	}

	firstID := signatures[0].(map[string]any)["signature_id"]
	secondID := signatures[1].(map[string]any)["signature_id"]

	if firstID != "sig:finance:0001" ||
		secondID != "sig:legal:0002" {
		t.Fatalf(
			"unexpected signature order: %v, %v",
			firstID,
			secondID,
		)
	}

	preservedBytes, err := sign.CanonicalBytes(signatures[1])
	if err != nil {
		t.Fatalf("canonical preserved signature: %v", err)
	}

	if string(firstBytes) != string(preservedBytes) {
		t.Fatal("append modified existing signature")
	}
}

func TestAppendRejectsDuplicateSignatureID(t *testing.T) {
	first, err := sign.Create(
		contextV1(),
		privateKey(t, 1),
		sign.Options{
			SignerID:    "authority:legal",
			KeyID:       "key:legal:2026-q3",
			SignatureID: "sig:legal:0002",
			SignedAt:    "2026-07-28T20:00:00Z",
		},
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = sign.Append(
		first,
		privateKey(t, 33),
		sign.Options{
			SignerID:    "authority:finance",
			KeyID:       "key:finance:2026-q3",
			SignatureID: "sig:legal:0002",
			SignedAt:    "2026-07-28T20:01:00Z",
		},
	)
	if err == nil {
		t.Fatal("duplicate signature ID unexpectedly accepted")
	}

	code, ok := sign.ErrorCode(err)
	if !ok || code != sign.CodeDuplicateSignatureID {
		t.Fatalf("unexpected error: code=%q err=%v", code, err)
	}
}

func TestParsePrivateKeyRejectsInvalidLength(t *testing.T) {
	raw := []byte(
		`{"algorithm":"ed25519","private_key":"AQID"}`,
	)

	_, err := sign.ParsePrivateKey(raw)
	if err == nil {
		t.Fatal("short private key unexpectedly accepted")
	}

	code, ok := sign.ErrorCode(err)
	if !ok || code != sign.CodeInvalidPrivateKey {
		t.Fatalf("unexpected error: code=%q err=%v", code, err)
	}
}

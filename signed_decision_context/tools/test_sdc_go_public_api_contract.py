#!/usr/bin/env python3
"""Validate the public Signed Decision Context Go v0.2.0 contract."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "signed_decision_context" / "go"
MODULE = "agpprotocol.org/agp/signed-decision-context"


def run(
    command: list[str],
    *,
    cwd: Path,
    expected_code: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != expected_code:
        raise AssertionError(
            f"command failed: {command!r}\n"
            f"cwd={cwd}\n"
            f"expected_code={expected_code}\n"
            f"actual_code={completed.returncode}\n"
            f"stdout={completed.stdout}\n"
            f"stderr={completed.stderr}"
        )

    return completed


def main() -> int:
    passed = 0

    run(["go", "test", "./sign"], cwd=GO_DIR)
    print("PASS  public sign package tests")
    passed += 1

    run(["go", "test", "./verify"], cwd=GO_DIR)
    print("PASS  public verify package tests")
    passed += 1

    with tempfile.TemporaryDirectory(
        prefix="agp-sdc-go-public-consumer-",
    ) as raw:
        temp = Path(raw)

        (temp / "go.mod").write_text(
            "module example.org/sdc-consumer\n\n"
            "go 1.22\n\n"
            f"require {MODULE} v0.0.0\n\n"
            f"replace {MODULE} => {GO_DIR}\n",
            encoding="utf-8",
        )

        (temp / "main.go").write_text(
            r'''package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"agpprotocol.org/agp/signed-decision-context/sign"
	verifyapi "agpprotocol.org/agp/signed-decision-context/verify"
)

func privateKey(seedStart byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = seedStart + byte(index)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func context() map[string]any {
	return map[string]any{
		"object_type": "agp.decision-context/1",
		"context_id":  "ctx:external:release:001",
		"created_at":  "2026-07-29T02:30:00Z",
		"expires_at":  nil,
		"policy": map[string]any{
			"id":      "policy:external:approval",
			"version": int64(1),
			"digest":  "1111111111111111111111111111111111111111111111111111111111111111",
		},
		"proposal": map[string]any{
			"type": "proposal:external:change",
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

func main() {
	legal := privateKey(1)
	finance := privateKey(33)

	first, err := sign.Create(
		context(),
		legal,
		sign.Options{
			SignerID:    "authority:legal",
			KeyID:       "key:legal:2026-q3",
			SignatureID: "sig:legal:0002",
			SignedAt:    "2026-07-29T02:30:00Z",
		},
	)
	if err != nil {
		panic(err)
	}

	second, err := sign.Append(
		first,
		finance,
		sign.Options{
			SignerID:    "authority:finance",
			KeyID:       "key:finance:2026-q3",
			SignatureID: "sig:finance:0001",
			SignedAt:    "2026-07-29T02:31:00Z",
		},
	)
	if err != nil {
		panic(err)
	}

	encoded, err := sign.CanonicalBytes(second)
	if err != nil {
		panic(err)
	}

	legalPublic := legal.Public().(ed25519.PublicKey)
	financePublic := finance.Public().(ed25519.PublicKey)

	keyringJSON := fmt.Sprintf(
		`{"keys":[`+
			`{"algorithm":"ed25519","key_id":"key:finance:2026-q3",`+
			`"public_key":"%s","signer_id":"authority:finance"},`+
			`{"algorithm":"ed25519","key_id":"key:legal:2026-q3",`+
			`"public_key":"%s","signer_id":"authority:legal"}]}`,
		base64.RawURLEncoding.EncodeToString(financePublic),
		base64.RawURLEncoding.EncodeToString(legalPublic),
	)

	keyring, err := verifyapi.ParseKeyring([]byte(keyringJSON))
	if err != nil {
		panic(err)
	}

	result, err := verifyapi.VerifyTyped(second, keyring)
	if err != nil {
		panic(err)
	}

	_, duplicateErr := sign.Append(
		second,
		finance,
		sign.Options{
			SignerID:    "authority:finance",
			KeyID:       "key:finance:2026-q3",
			SignatureID: "sig:finance:0001",
			SignedAt:    "2026-07-29T02:32:00Z",
		},
	)

	code, ok := sign.ErrorCode(duplicateErr)
	if !ok {
		panic("duplicate error is not typed")
	}

	fmt.Printf(
		"SDC_EXTERNAL_CONSUMER_PASS "+
			"signatures=%d verified=%d bytes=%d duplicate=%s\n",
		result.SignatureCount,
		result.VerifiedSignatureCount,
		len(encoded),
		code,
	)
}
''',
            encoding="utf-8",
        )

        run(["go", "mod", "tidy"], cwd=temp)
        print("PASS  external consumer resolves public packages")
        passed += 1

        external = run(["go", "run", "."], cwd=temp)

        marker = (
            "SDC_EXTERNAL_CONSUMER_PASS "
            "signatures=2 verified=2"
        )
        if marker not in external.stdout:
            raise AssertionError(
                f"unexpected external output: {external.stdout!r}"
            )
        print("PASS  external consumer creates signed context")
        passed += 1

        if "verified=2" not in external.stdout:
            raise AssertionError(
                f"external verification failed: {external.stdout!r}"
            )
        print("PASS  external consumer verifies both signatures")
        passed += 1

        if "duplicate=DUPLICATE_SIGNATURE_ID" not in (
            external.stdout
        ):
            raise AssertionError(
                f"typed error missing: {external.stdout!r}"
            )
        print("PASS  external consumer receives typed signing error")
        passed += 1

        source = (temp / "main.go").read_text(encoding="utf-8")

        if "/internal/" in source:
            raise AssertionError(
                "external consumer imports an internal package"
            )
        if f'"{MODULE}/sign"' not in source:
            raise AssertionError(
                "external consumer does not import public sign package"
            )
        if f'"{MODULE}/verify"' not in source:
            raise AssertionError(
                "external consumer does not import public verify package"
            )

        print("PASS  external consumer uses only public packages")
        passed += 1

    module_text = (GO_DIR / "go.mod").read_text(encoding="utf-8")

    if "\nreplace " in "\n" + module_text:
        raise AssertionError(
            "released module go.mod contains a replace directive"
        )

    print("PASS  module metadata contains no replace directive")
    passed += 1

    print(
        "Signed Decision Context Go public API contract: "
        f"{passed}/{passed} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

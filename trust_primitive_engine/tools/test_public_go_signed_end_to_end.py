#!/usr/bin/env python3
"""Test the public SDC signer and TPE evaluator together without replace."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


SDC_MODULE = "agpprotocol.org/agp/signed-decision-context"
SDC_VERSION = "v0.2.0"

TPE_MODULE = "agpprotocol.org/agp/trust-primitive-engine"
TPE_VERSION = "v0.2.2"


class TestFailure(RuntimeError):
    pass


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        raise TestFailure(
            f"command failed: {command!r}\n"
            f"cwd={cwd}\n"
            f"exit={completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )

    return completed


def module_version(
    modules: list[dict[str, Any]],
    module_path: str,
) -> str | None:
    for item in modules:
        if item.get("Path") == module_path:
            return item.get("Version")
    return None


def main() -> int:
    passed = 0
    total = 8

    environment = dict(os.environ)
    environment["GOPROXY"] = "https://proxy.golang.org,direct"

    with tempfile.TemporaryDirectory(
        prefix="agp-public-go-e2e-",
    ) as raw_temp:
        temp = Path(raw_temp)

        (temp / "go.mod").write_text(
            "module example.org/agp-public-go-e2e\n\n"
            "go 1.22\n\n"
            "require (\n"
            f"\t{SDC_MODULE} {SDC_VERSION}\n"
            f"\t{TPE_MODULE} {TPE_VERSION}\n"
            ")\n",
            encoding="utf-8",
        )

        source = r'''package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"agpprotocol.org/agp/signed-decision-context/sign"
	"agpprotocol.org/agp/trust-primitive-engine/tpe"
)

func privateKey(start byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)

	for index := range seed {
		seed[index] = start + byte(index)
	}

	return ed25519.NewKeyFromSeed(seed)
}

func decisionContext() map[string]any {
	return map[string]any{
		"object_type": "agp.decision-context/1",
		"context_id":  "ctx:public:e2e:001",
		"created_at":  "2026-07-29T03:00:00Z",
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
			map[string]any{
				"id":     "authority:finance",
				"role":   "approver",
				"weight": int64(1),
			},
		},
		"evidence":    []any{},
		"constraints": []any{},
	}
}

func keyring(
	legal ed25519.PrivateKey,
	finance ed25519.PrivateKey,
) []byte {
	legalPublic := legal.Public().(ed25519.PublicKey)
	financePublic := finance.Public().(ed25519.PublicKey)

	value := map[string]any{
		"keys": []any{
			map[string]any{
				"signer_id": "authority:finance",
				"key_id":    "key:finance:2026-q3",
				"algorithm": "ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(
					financePublic,
				),
			},
			map[string]any{
				"signer_id": "authority:legal",
				"key_id":    "key:legal:2026-q3",
				"algorithm": "ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(
					legalPublic,
				),
			},
		},
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	return encoded
}

func policy() tpe.Policy {
	return tpe.Policy{
		ObjectType:    "agp.trust-policy/2",
		PolicyID:      "policy:example:approval",
		Version:       1,
		EligibleRoles: []string{"approver"},
		Requirements: []map[string]any{
			{
				"requirement_id": "requirement:legal",
				"type":           "required_signer",
				"signer_id":      "authority:legal",
			},
			{
				"requirement_id": "requirement:finance",
				"type":           "required_signer",
				"signer_id":      "authority:finance",
			},
		},
	}
}

func main() {
	legal := privateKey(1)
	finance := privateKey(33)

	first, err := sign.Create(
		decisionContext(),
		legal,
		sign.Options{
			SignerID:    "authority:legal",
			KeyID:       "key:legal:2026-q3",
			SignatureID: "sig:legal:0002",
			SignedAt:    "2026-07-29T03:00:00Z",
		},
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("PUBLIC_E2E_CREATE_PASS signatures=1")

	second, err := sign.Append(
		first,
		finance,
		sign.Options{
			SignerID:    "authority:finance",
			KeyID:       "key:finance:2026-q3",
			SignatureID: "sig:finance:0001",
			SignedAt:    "2026-07-29T03:01:00Z",
		},
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("PUBLIC_E2E_APPEND_PASS signatures=2")

	signedJSON, err := sign.CanonicalBytes(second)
	if err != nil {
		panic(err)
	}

	keyringJSON := keyring(legal, finance)

	evaluation, err := tpe.EvaluateSigned(
		signedJSON,
		keyringJSON,
		policy(),
		nil,
	)
	if err != nil {
		panic(err)
	}

	if evaluation.Status != "satisfied" {
		panic("expected satisfied evaluation")
	}

	if len(evaluation.VerifiedSigners) != 2 {
		panic("expected two verified signers")
	}

	fmt.Printf(
		"PUBLIC_E2E_EVALUATE_PASS status=%s verified=%d\n",
		evaluation.Status,
		len(evaluation.VerifiedSigners),
	)

	var tampered map[string]any

	if err := json.Unmarshal(signedJSON, &tampered); err != nil {
		panic(err)
	}

	signatures := tampered["signatures"].([]any)
	entry := signatures[0].(map[string]any)
	signatureText := entry["signature"].(string)

	if signatureText[0] == 'A' {
		entry["signature"] = "B" + signatureText[1:]
	} else {
		entry["signature"] = "A" + signatureText[1:]
	}

	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		panic(err)
	}

	_, tamperedErr := tpe.EvaluateSigned(
		tamperedJSON,
		keyringJSON,
		policy(),
		nil,
	)

	if tamperedErr == nil {
		panic("tampered signature unexpectedly accepted")
	}

	code, ok := tpe.ErrorCode(tamperedErr)
	if !ok {
		panic("tampered failure is not typed")
	}

	if string(code) != "SIGNATURE_VERIFICATION_FAILED" {
		panic(
			fmt.Sprintf(
				"unexpected tampered error code: %s",
				code,
			),
		)
	}

	fmt.Printf(
		"PUBLIC_E2E_TAMPERED_PASS code=%s\n",
		code,
	)
}
'''

        (temp / "main.go").write_text(
            source,
            encoding="utf-8",
        )

        run(
            ["go", "mod", "tidy"],
            cwd=temp,
            env=environment,
        )
        print("PASS  public modules resolve without replace")
        passed += 1

        go_mod = (temp / "go.mod").read_text(encoding="utf-8")

        if "\nreplace " in "\n" + go_mod:
            raise TestFailure(
                "external consumer go.mod contains replace"
            )

        print("PASS  external consumer contains no replace")
        passed += 1

        listed = run(
            ["go", "list", "-m", "-json", "all"],
            cwd=temp,
            env=environment,
        )

        decoder = json.JSONDecoder()
        raw = listed.stdout
        offset = 0
        modules: list[dict[str, Any]] = []

        while offset < len(raw):
            while offset < len(raw) and raw[offset].isspace():
                offset += 1

            if offset >= len(raw):
                break

            item, end = decoder.raw_decode(raw, offset)
            modules.append(item)
            offset = end

        sdc_version = module_version(modules, SDC_MODULE)
        tpe_version = module_version(modules, TPE_MODULE)

        if sdc_version != SDC_VERSION:
            raise TestFailure(
                f"unexpected SDC version: {sdc_version}"
            )

        if tpe_version != TPE_VERSION:
            raise TestFailure(
                f"unexpected TPE version: {tpe_version}"
            )

        print(
            "PASS  effective public versions "
            f"sdc={sdc_version} tpe={tpe_version}"
        )
        passed += 1

        executed = run(
            ["go", "run", "."],
            cwd=temp,
            env=environment,
        )

        markers = (
            "PUBLIC_E2E_CREATE_PASS signatures=1",
            "PUBLIC_E2E_APPEND_PASS signatures=2",
            "PUBLIC_E2E_EVALUATE_PASS status=satisfied verified=2",
            "PUBLIC_E2E_TAMPERED_PASS "
            "code=SIGNATURE_VERIFICATION_FAILED",
        )

        labels = (
            "public SDC creation succeeds",
            "public SDC append succeeds",
            "public signed TPE evaluation is satisfied",
            "tampered signature returns stable typed error",
        )

        for marker, label in zip(markers, labels, strict=True):
            if marker not in executed.stdout:
                raise TestFailure(
                    f"missing marker {marker!r}\n"
                    f"stdout:\n{executed.stdout}"
                )

            print(f"PASS  {label}")
            passed += 1

        if "/internal/" in source:
            raise TestFailure(
                "external consumer imports an internal package"
            )

        required_imports = (
            '"agpprotocol.org/agp/'
            'signed-decision-context/sign"',
            '"agpprotocol.org/agp/'
            'trust-primitive-engine/tpe"',
        )

        for required in required_imports:
            if required not in source:
                raise TestFailure(
                    f"missing public import: {required}"
                )

        print("PASS  external consumer uses only public packages")
        passed += 1

    print(
        "AGP public Go signed end-to-end integration: "
        f"{passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

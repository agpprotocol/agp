#!/usr/bin/env python3
"""Validate the stable external Go API and quick-start example."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "trust_primitive_engine/go"
EXAMPLE = GO_DIR / "examples/basic-evaluation/main.go"


def run(
    command: list[str],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed: {command!r}\n"
            f"cwd={cwd}\n"
            f"stdout={completed.stdout}\n"
            f"stderr={completed.stderr}"
        )
    return completed


def main() -> int:
    passed = 0

    run(["go", "test", "./tpe"], cwd=GO_DIR)
    print("PASS  public package tests")
    passed += 1

    example = run(
        ["go", "run", "./examples/basic-evaluation"],
        cwd=GO_DIR,
    )
    print("PASS  public quick-start executes")
    passed += 1

    result = json.loads(example.stdout)
    if result.get("status") != "satisfied":
        raise AssertionError(
            f"unexpected quick-start status: {result.get('status')!r}"
        )
    print("PASS  public quick-start returns satisfied")
    passed += 1

    example_text = EXAMPLE.read_text(encoding="utf-8")
    if "/internal/" in example_text:
        raise AssertionError(
            "public quick-start imports an internal package"
        )
    if (
        '"agpprotocol.org/agp/trust-primitive-engine/tpe"'
        not in example_text
    ):
        raise AssertionError("public quick-start does not import tpe")
    print("PASS  public quick-start uses only public package")
    passed += 1

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-go-public-consumer-"
    ) as raw:
        temp = Path(raw)

        (temp / "go.mod").write_text(
            "module example.org/tpe-consumer\n\n"
            "go 1.22\n\n"
            "require "
            "agpprotocol.org/agp/trust-primitive-engine "
            "v0.0.0\n\n"
            "replace "
            "agpprotocol.org/agp/trust-primitive-engine "
            f"=> {GO_DIR}\n",
            encoding="utf-8",
        )

        (temp / "main.go").write_text(
            """package main

import (
    "fmt"

    "agpprotocol.org/agp/trust-primitive-engine/tpe"
)

func main() {
    result, err := tpe.Evaluate(
        tpe.EvaluationInput{
            Context: tpe.Context{
                ContextID: "context:external",
                Policy: tpe.PolicyBinding{
                    ID:      "policy:external",
                    Version: 1,
                    Digest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            },
        },
        tpe.Policy{
            PolicyID:      "policy:external",
            Version:       1,
            EligibleRoles: []string{"approver"},
            Requirements: []map[string]any{
                {
                    "requirement_id": "requirement:external",
                    "type":           "required_signer",
                    "signer_id":      "authority:approver-a",
                },
            },
        },
        nil,
    )
    if err != nil {
        panic(err)
    }

    fmt.Printf("EXTERNAL_GO_TPE_PASS status=%s\\n", result.Status)
}
""",
            encoding="utf-8",
        )

        run(["go", "mod", "tidy"], cwd=temp)
        external = run(["go", "run", "."], cwd=temp)
        if "EXTERNAL_GO_TPE_PASS status=unsatisfied" not in (
            external.stdout
        ):
            raise AssertionError(
                f"unexpected external output: {external.stdout}"
            )

    print("PASS  external Go consumer compiles and executes")
    passed += 1

    print(
        "TPE Go stable public API contract: "
        f"{passed}/{passed} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

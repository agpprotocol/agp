#!/usr/bin/env python3
"""Validate the Trust Primitive Engine Go v0.2.2 release contract."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE_GO = ROOT / "trust_primitive_engine/go"

SDC_MODULE = "agpprotocol.org/agp/signed-decision-context"
SDC_VERSION = "v0.2.0"
TPE_MODULE = "agpprotocol.org/agp/trust-primitive-engine"


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


def decode_module_stream(raw: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    modules: list[dict[str, Any]] = []
    offset = 0

    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1

        if offset >= len(raw):
            break

        item, offset = decoder.raw_decode(raw, offset)
        modules.append(item)

    return modules


def version_for(
    modules: list[dict[str, Any]],
    module_path: str,
) -> str | None:
    for item in modules:
        if item.get("Path") == module_path:
            return item.get("Version")

    return None


def main() -> int:
    total = 7
    passed = 0

    go_mod_path = TPE_GO / "go.mod"
    go_sum_path = TPE_GO / "go.sum"

    go_mod = go_mod_path.read_text(encoding="utf-8")
    go_sum = go_sum_path.read_text(encoding="utf-8")

    expected_requirement = (
        f"require {SDC_MODULE} {SDC_VERSION}"
    )

    if expected_requirement not in go_mod:
        raise TestFailure(
            f"missing module requirement: {expected_requirement}"
        )

    print(
        "PASS  TPE module requires "
        f"signed-decision-context {SDC_VERSION}"
    )
    passed += 1

    for line in go_mod.splitlines():
        if line.strip().startswith("replace "):
            raise TestFailure(
                "TPE public module contains replace directive"
            )

    print("PASS  TPE public module contains no replace")
    passed += 1

    required_sum = f"{SDC_MODULE} {SDC_VERSION} "
    obsolete_sum = f"{SDC_MODULE} v0.1.0 "

    if required_sum not in go_sum:
        raise TestFailure(
            "go.sum does not contain SDC v0.2.0"
        )

    if obsolete_sum in go_sum:
        raise TestFailure(
            "go.sum still contains obsolete SDC v0.1.0"
        )

    print("PASS  go.sum is aligned to SDC v0.2.0")
    passed += 1

    run(
        ["go", "test", "./..."],
        cwd=TPE_GO,
    )
    run(
        ["go", "vet", "./..."],
        cwd=TPE_GO,
    )

    print("PASS  TPE public Go packages pass test and vet")
    passed += 1

    environment = dict(os.environ)
    environment["GOPROXY"] = (
        "https://proxy.golang.org,direct"
    )

    example = (
        TPE_GO
        / "examples/external-integration/satisfied"
    )

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-v022-release-contract-",
    ) as raw_temp:
        temp = Path(raw_temp)

        shutil.copy2(
            example / "main.go",
            temp / "main.go",
        )
        shutil.copy2(
            example / "signed-context.json",
            temp / "signed-context.json",
        )
        shutil.copy2(
            example / "keyring.json",
            temp / "keyring.json",
        )

        (temp / "go.mod").write_text(
            "module example.org/tpe-v022-release-contract\n\n"
            "go 1.22\n\n"
            f"require {TPE_MODULE} v0.0.0\n\n"
            f"replace {TPE_MODULE} => {TPE_GO}\n",
            encoding="utf-8",
        )

        run(
            ["go", "mod", "tidy"],
            cwd=temp,
            env=environment,
        )

        listed = run(
            ["go", "list", "-m", "-json", "all"],
            cwd=temp,
            env=environment,
        )

        modules = decode_module_stream(listed.stdout)
        sdc_version = version_for(modules, SDC_MODULE)

        if sdc_version != SDC_VERSION:
            raise TestFailure(
                "external consumer resolved unexpected "
                f"SDC version: {sdc_version}"
            )

        print(
            "PASS  external consumer resolves "
            f"SDC {sdc_version}"
        )
        passed += 1

        executed = run(
            ["go", "run", "."],
            cwd=temp,
            env=environment,
        )

        expected_marker = (
            "EXTERNAL_TPE_SATISFIED_PASS "
            "status=satisfied signer=authority:legal"
        )

        if expected_marker not in executed.stdout:
            raise TestFailure(
                f"missing marker: {expected_marker}\n"
                f"stdout:\n{executed.stdout}"
            )

        print(
            "PASS  external consumer evaluates "
            "a signed context as satisfied"
        )
        passed += 1

        source = (temp / "main.go").read_text(
            encoding="utf-8"
        )

        if "/internal/" in source:
            raise TestFailure(
                "external consumer imports internal package"
            )

        public_import = (
            '"agpprotocol.org/agp/'
            'trust-primitive-engine/tpe"'
        )

        if public_import not in source:
            raise TestFailure(
                "external consumer does not use public TPE API"
            )

        print(
            "PASS  external consumer uses only "
            "the public TPE package"
        )
        passed += 1

    print(
        "Trust Primitive Engine Go v0.2.2 "
        f"release contract: {passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

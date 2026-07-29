#!/usr/bin/env python3
"""Validate current public Go release references and compatibility metadata."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

TPE_VERSION = "v0.2.2"
SDC_VERSION = "v0.2.0"

TPE_MODULE = "agpprotocol.org/agp/trust-primitive-engine"
SDC_MODULE = "agpprotocol.org/agp/signed-decision-context"


class TestFailure(RuntimeError):
    pass


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise TestFailure(detail)


def main() -> int:
    total = 6
    passed = 0

    e2e_path = (
        ROOT
        / "trust_primitive_engine/tools/"
        "test_public_go_signed_end_to_end.py"
    )
    e2e = e2e_path.read_text(encoding="utf-8")

    require(
        f'TPE_VERSION = "{TPE_VERSION}"' in e2e,
        "end-to-end guard does not pin TPE v0.2.2",
    )
    require(
        f'SDC_VERSION = "{SDC_VERSION}"' in e2e,
        "end-to-end guard does not pin SDC v0.2.0",
    )

    print(
        "PASS  end-to-end guard pins "
        f"TPE {TPE_VERSION} and SDC {SDC_VERSION}"
    )
    passed += 1

    go_mod_path = ROOT / "trust_primitive_engine/go/go.mod"
    go_mod = go_mod_path.read_text(encoding="utf-8")

    require(
        f"require {SDC_MODULE} {SDC_VERSION}" in go_mod,
        "TPE go.mod does not require SDC v0.2.0",
    )

    print("PASS  TPE module requires SDC v0.2.0")
    passed += 1

    replace_lines = [
        line
        for line in go_mod.splitlines()
        if re.match(r"^\s*replace\s", line)
    ]

    require(
        not replace_lines,
        "TPE public module contains replace directive",
    )

    print("PASS  TPE public module contains no replace")
    passed += 1

    external_readme = (
        ROOT
        / "trust_primitive_engine/go/examples/"
        "external-integration/README.md"
    ).read_text(encoding="utf-8")

    require(
        f"go get {TPE_MODULE}@{TPE_VERSION}"
        in external_readme,
        "external integration guide does not install TPE v0.2.2",
    )

    print("PASS  external integration guide installs TPE v0.2.2")
    passed += 1

    tpe_readme = (
        ROOT / "trust_primitive_engine/go/README.md"
    ).read_text(encoding="utf-8")

    require(
        f"go get {TPE_MODULE}@{TPE_VERSION}" in tpe_readme,
        "TPE README does not install v0.2.2",
    )
    require(
        f"{SDC_MODULE} {SDC_VERSION}" in tpe_readme,
        "TPE README does not declare SDC v0.2.0 compatibility",
    )

    print("PASS  TPE README declares the current public pair")
    passed += 1

    compatibility = (
        ROOT
        / "trust_primitive_engine/go/"
        "PUBLIC-GO-COMPATIBILITY.md"
    ).read_text(encoding="utf-8")

    required_markers = (
        f"{TPE_MODULE} v0.2.2",
        f"{SDC_MODULE} v0.2.0",
        "No `replace` directive is required.",
        "test_public_go_signed_end_to_end.py",
    )

    for marker in required_markers:
        require(
            marker in compatibility,
            f"compatibility matrix missing marker: {marker}",
        )

    print("PASS  public compatibility matrix is complete")
    passed += 1

    print(
        "AGP public Go release alignment: "
        f"{passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

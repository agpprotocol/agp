#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONSTRAINTS = ROOT / "constraints-ci.txt"
REQUIREMENTS = ROOT / "requirements-v0.4.txt"
PYPROJECT = ROOT / "pyproject.toml"
WORKFLOW_DIR = ROOT / ".github/workflows"
EXPECTED_TOTAL = 12

EXPECTED_PINS = {
    "pip": "26.1.2",
    "build": "1.5.0",
    "twine": "6.2.0",
    "hatchling": "1.27.0",
    "cryptography": "49.0.0",
    "jsonschema": "4.26.0",
    "hypothesis": "6.161.1",
}

def parse_constraints(text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)",
            line,
        )
        if match is not None:
            pins[match.group(1).lower()] = match.group(2)
    return pins

def main() -> int:
    constraints_text = CONSTRAINTS.read_text(encoding="utf-8") if CONSTRAINTS.is_file() else ""
    requirements_text = REQUIREMENTS.read_text(encoding="utf-8") if REQUIREMENTS.is_file() else ""
    pyproject_text = PYPROJECT.read_text(encoding="utf-8") if PYPROJECT.is_file() else ""
    workflows = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml"))
    }
    pins = parse_constraints(constraints_text)
    all_workflows = "\n".join(workflows.values())

    checks = [
        ("CI constraints file exists", CONSTRAINTS.is_file()),
        ("reviewed direct pin inventory is exact", pins == EXPECTED_PINS),
        ("runtime requirements retain compatibility ranges", all(
            marker in requirements_text
            for marker in ("cryptography>=42.0", "jsonschema>=4.26,<5", "hypothesis>=6.135,<7")
        )),
        ("historical conformance uses CI constraints",
         "python -m pip install -c constraints-ci.txt -r requirements-v0.4.txt"
         in workflows.get("conformance.yml", "")),
        ("TPE conformance pins pip",
         "python -m pip install pip==26.1.2"
         in workflows.get("tpe-conformance.yml", "")),
        ("TPE conformance uses CI constraints",
         "python -m pip install -c constraints-ci.txt -r requirements-v0.4.txt"
         in workflows.get("tpe-conformance.yml", "")),
        ("TPE cache includes constraints",
         "constraints-ci.txt" in workflows.get("tpe-conformance.yml", "")),
        ("publishing pins build and twine",
         "python -m pip install build==1.5.0 twine==6.2.0"
         in workflows.get("publish-pypi.yml", "")),
        ("publishing constrains isolated builds",
         "PIP_CONSTRAINT: constraints-ci.txt"
         in workflows.get("publish-pypi.yml", "")),
        ("root build backend is exact",
         'requires = ["hatchling==1.27.0"]' in pyproject_text),
        ("moving pip upgrade commands are absent",
         "pip install --upgrade" not in all_workflows),
        ("constraints are watched by TPE workflow",
         workflows.get("tpe-conformance.yml", "").count('- "constraints-ci.txt"') == 2),
    ]

    passed = 0
    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print("AGP Python dependency reproducibility contract: "
          f"{passed}/{EXPECTED_TOTAL} passed")
    return 0 if passed == EXPECTED_TOTAL else 1

if __name__ == "__main__":
    raise SystemExit(main())

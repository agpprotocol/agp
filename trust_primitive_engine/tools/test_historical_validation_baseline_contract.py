#!/usr/bin/env python3
# Contract for explicit historical validation baseline binding.

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "recover_preexisting_release_candidate.py"
)
EXPECTED_TOTAL = 22


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")
    checks = [
        ("recovery tool remains present", TOOL.is_file()),
        (
            "historical total is explicit",
            '"--expected-validation-total"' in text,
        ),
        (
            "historical runner digest is explicit",
            '"--expected-validation-runner-sha256"' in text,
        ),
        (
            "runner SHA-256 format is fixed",
            'SHA256 = re.compile(r"^[0-9a-f]{64}$")' in text,
        ),
        (
            "expected total must be positive",
            "expected validation total must be positive" in text,
        ),
        (
            "runner digest must be valid",
            "expected validation runner SHA-256 is invalid" in text,
        ),
        (
            "historical runner bytes are hashed",
            "runner_raw = runner_path.read_bytes()" in text
            and "runner_sha256 = sha256_bytes(runner_raw)" in text,
        ),
        (
            "runner digest mismatch is rejected",
            "historical validation runner SHA-256 mismatch"
            in text,
        ),
        (
            "tag runner is executed by absolute path",
            "[sys.executable, str(runner_path)]" in text,
        ),
        (
            "validation summary remains mandatory",
            "global validation summary was not found" in text,
        ),
        (
            "partial validation remains rejected",
            "global validation did not fully pass" in text,
        ),
        (
            "unexpected historical total is rejected",
            "unexpected historical validation total" in text,
        ),
        (
            "hardcoded historical total is removed",
            "EXPECTED_TOTAL = 1317" not in text,
        ),
        (
            "candidate keeps observed validation total",
            '"validation_total": validation_total' in text,
        ),
        (
            "recovery records runner digest",
            '"validation_runner_sha256": (' in text,
        ),
        (
            "recovery records baseline source",
            "explicit-historical-tag-runner" in text,
        ),
        (
            "output reports runner digest",
            "RECOVERED_VALIDATION_RUNNER_SHA256=" in text,
        ),
        (
            "Git tag alignment remains required",
            "local release tag does not peel to source commit"
            in text
            and "remote release tag does not peel to source commit"
            in text,
        ),
        (
            "Release absence remains required",
            "GitHub Release already exists" in text,
        ),
        (
            "PyPI absence remains required",
            "candidate version already exists on PyPI" in text,
        ),
        (
            "no authorization is created",
            "AUTHORIZATION_CREATED=no" in text
            and '"creates_authorization": False' in text,
        ),
        (
            "recovery remains read-only",
            "gh release create" not in text
            and "gh release edit" not in text
            and "gh release upload" not in text
            and "git tag " not in text
            and "git push" not in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP historical validation baseline contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())

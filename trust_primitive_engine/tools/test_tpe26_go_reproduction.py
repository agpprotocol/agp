#!/usr/bin/env python3
# Cross-language reproduction of the frozen TPE 2.6 golden profile.

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "trust_primitive_engine/go"
CORPUS = ROOT / "trust_primitive_engine/fixtures/golden/v2.6"


class TestFailure(Exception):
    pass


def compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def main() -> int:
    manifest = json.loads(
        (CORPUS / "manifest.json").read_text(encoding="utf-8")
    )

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-reproduction-"
    ) as raw:
        binary = Path(raw) / "agp-tpe26-reproduce"

        subprocess.run(
            [
                "go",
                "build",
                "-trimpath",
                "-o",
                str(binary),
                "./cmd/agp-tpe26-reproduce",
            ],
            cwd=GO_DIR,
            check=True,
        )

        passed = 0
        for case in manifest["cases"]:
            case_dir = CORPUS / case["directory"]
            expected_value = json.loads(
                (case_dir / "expected-evaluation.json").read_text(
                    encoding="utf-8"
                )
            )
            expected_bytes = compact_json(expected_value)
            expected_hash = hashlib.sha256(expected_bytes).hexdigest()
            frozen_hash = (
                case_dir / "expected-evaluation.sha256"
            ).read_text(encoding="ascii").strip()

            completed = subprocess.run(
                [
                    str(binary),
                    str(case_dir / "evaluation-input.json"),
                    str(case_dir / "root-policy.json"),
                    str(case_dir / "policy-set.json"),
                ],
                cwd=Path(raw),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                raise TestFailure(
                    f"{case['name']}: Go reproducer failed\n"
                    f"{completed.stderr.decode('utf-8', errors='replace')}"
                )

            actual_bytes = completed.stdout
            actual_hash = hashlib.sha256(actual_bytes).hexdigest()

            if expected_hash != frozen_hash:
                raise TestFailure(
                    f"{case['name']}: frozen file hash differs"
                )
            if expected_hash != case["expected_sha256"]:
                raise TestFailure(
                    f"{case['name']}: manifest hash differs"
                )
            if actual_bytes != expected_bytes:
                raise TestFailure(
                    f"{case['name']}: Python/Go bytes differ\n"
                    f"expected={expected_bytes.decode('utf-8')}\n"
                    f"actual={actual_bytes.decode('utf-8', errors='replace')}"
                )
            if actual_hash != expected_hash:
                raise TestFailure(
                    f"{case['name']}: Python/Go SHA-256 differs"
                )

            status = json.loads(actual_bytes)["status"]
            if status != case["expected_status"]:
                raise TestFailure(f"{case['name']}: status differs")

            print(
                f"PASS  {case['name']:<34} "
                f"status={status} "
                f"sha256={actual_hash[:12]}... "
                "python_go=byte-identical"
            )
            passed += 1

        if passed != 7:
            raise TestFailure(f"expected 7 passed cases, got {passed}")

        print(
            "TPE 2.6 Python/Go frozen-profile reproduction: "
            "7/7 passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

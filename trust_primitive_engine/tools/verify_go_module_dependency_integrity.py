#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

MODULE_DIRS = (
    Path("canonicalization/go"),
    Path("decision_context/go"),
    Path("decision/signed/go"),
    Path("go"),
    Path("registry/go"),
    Path("signed_decision_context/go"),
    Path("signed/go"),
    Path("transparency/go"),
    Path("trust_primitive_engine/go"),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], cwd: Path, env: dict[str, str]) -> int:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    return completed.returncode


def main() -> int:
    environment = os.environ.copy()
    environment.setdefault("GOPROXY", "https://proxy.golang.org,direct")
    environment.setdefault("GOSUMDB", "sum.golang.org")

    passed = 0
    expected = len(MODULE_DIRS) * 3

    with tempfile.TemporaryDirectory(prefix="agp-go-module-integrity-") as temp_dir:
        temp_root = Path(temp_dir)

        for module_dir in MODULE_DIRS:
            source = ROOT / module_dir
            destination = temp_root / module_dir
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)

            go_mod = destination / "go.mod"
            go_sum = destination / "go.sum"

            before_mod = sha256(go_mod)
            before_sum = sha256(go_sum) if go_sum.is_file() else None

            verify_code = run(["go", "mod", "verify"], destination, environment)
            if verify_code == 0:
                passed += 1
                print(f"PASS  {module_dir} go mod verify")
            else:
                print(f"FAIL  {module_dir} go mod verify", file=sys.stderr)

            list_code = run(["go", "list", "-m", "all"], destination, environment)
            if list_code == 0:
                passed += 1
                print(f"PASS  {module_dir} module graph resolves")
            else:
                print(f"FAIL  {module_dir} module graph resolves", file=sys.stderr)

            tidy_code = run(["go", "mod", "tidy"], destination, environment)
            after_mod = sha256(go_mod)
            after_sum = sha256(go_sum) if go_sum.is_file() else None
            tidy_clean = (
                tidy_code == 0
                and before_mod == after_mod
                and before_sum == after_sum
            )
            if tidy_clean:
                passed += 1
                print(f"PASS  {module_dir} go mod tidy is stable")
            else:
                print(f"FAIL  {module_dir} go mod tidy is stable", file=sys.stderr)

    print(f"AGP Go module dependency integrity: {passed}/{expected} passed")
    return 0 if passed == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())

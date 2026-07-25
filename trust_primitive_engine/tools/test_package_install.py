#!/usr/bin/env python3
"""Build and smoke-test the agp-tpe wheel in a clean virtual environment."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run(command: list[str], *, cwd: Path = ROOT) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="agp-tpe-package-") as raw:
        temp = Path(raw)
        dist = temp / "dist"
        env_dir = temp / "venv"

        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--wheel-dir",
                str(dist),
            ]
        )

        wheels = sorted(dist.glob("agp_tpe-*.whl"))
        if len(wheels) != 1:
            raise AssertionError(
                f"expected one agp-tpe wheel, found: {wheels}"
            )

        venv.EnvBuilder(with_pip=True).create(env_dir)

        python = (
            env_dir / "Scripts/python.exe"
            if os.name == "nt"
            else env_dir / "bin/python"
        )

        run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                str(wheels[0]),
            ]
        )

        run(
            [
                str(python),
                "-c",
                (
                    "from trust_primitive_engine import "
                    "evaluate_trust_policy, "
                    "TrustPolicyEvaluationError, "
                    "DEFAULT_SCHEMA_DIR; "
                    "assert DEFAULT_SCHEMA_DIR.is_dir(); "
                    "assert callable(evaluate_trust_policy); "
                    "assert issubclass(TrustPolicyEvaluationError, Exception); "
                    "print('AGP_TPE_WHEEL_IMPORT_PASS'); "
                    "print(DEFAULT_SCHEMA_DIR)"
                ),
            ]
        )

        print(f"PASS built wheel: {wheels[0].name}")
        print("AGP TPE package installation: 1/1 passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

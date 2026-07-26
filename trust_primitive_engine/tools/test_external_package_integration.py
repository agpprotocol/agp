#!/usr/bin/env python3
"""Build and run an external agp-tpe integration outside the repository."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = ROOT / "trust_primitive_engine/examples/external-package"


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed: {command!r}\n"
            f"cwd={cwd}\n"
            f"returncode={completed.returncode}\n"
            f"stdout={completed.stdout or ''}\n"
            f"stderr={completed.stderr or ''}"
        )
    return completed


def main() -> int:
    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-external-integration-"
    ) as raw:
        temp = Path(raw)
        dist = temp / "dist"
        env_dir = temp / "venv"
        run_dir = temp / "outside-repository"
        dist.mkdir()
        run_dir.mkdir()

        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--wheel-dir",
                str(dist),
            ],
            cwd=ROOT,
        )
        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--wheel-dir",
                str(dist),
            ],
            cwd=EXTERNAL,
        )

        agp_wheels = sorted(dist.glob("agp_tpe-2.5.0-*.whl"))
        example_wheels = sorted(
            dist.glob("tpe24_external_example-1.0.0-*.whl")
        )
        assert len(agp_wheels) == 1, agp_wheels
        assert len(example_wheels) == 1, example_wheels

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
                str(agp_wheels[0]),
            ],
            cwd=run_dir,
        )
        run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-deps",
                str(example_wheels[0]),
            ],
            cwd=run_dir,
        )

        clean_env = dict(os.environ)
        clean_env.pop("PYTHONPATH", None)
        clean_env["PYTHONNOUSERSITE"] = "1"

        completed = run(
            [str(python), "-m", "tpe24_external_example"],
            cwd=run_dir,
            env=clean_env,
            capture=True,
        )
        output = completed.stdout

        assert "TPE_2_4_EXTERNAL_PACKAGE_PASS" in output, output
        assert "RESULT_STATUS=satisfied" in output, output

        module_lines = [
            line for line in output.splitlines()
            if line.startswith("TPE_MODULE_PATH=")
        ]
        assert len(module_lines) == 1, output

        module_path = Path(module_lines[0].split("=", 1)[1]).resolve()
        if ROOT == module_path or ROOT in module_path.parents:
            raise AssertionError(
                f"module imported from repository checkout: {module_path}"
            )
        if "site-packages" not in module_path.parts:
            raise AssertionError(
                f"module was not imported from site-packages: {module_path}"
            )

        print(output, end="")
        print("TPE 2.4 external package integration: 1/1 passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

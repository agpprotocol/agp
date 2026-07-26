#!/usr/bin/env python3
"""Build and audit the agp-tpe wheel in a clean virtual environment."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import venv
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_SCHEMAS = ROOT / "registry/schemas"
SIGNED_DC3_FIXTURE = (
    ROOT
    / "trust_primitive_engine/examples/external-package-tpe26/src/"
    "tpe26_external_reproduction/fixtures/satisfied/signed-context.json"
)

REQUIRED_SCHEMAS = {
    "agp.canonicalization-receipt-1.schema.json",
    "agp.decision-context-1.schema.json",
    "agp.decision-context-2.schema.json",
    "agp.decision-context-3.schema.json",
    "agp.signature-statement-1.schema.json",
    "agp.signature-statement-2.schema.json",
    "agp.signature-statement-3.schema.json",
    "agp.signed-decision-context-1.schema.json",
    "agp.signed-decision-context-2.schema.json",
    "agp.signed-decision-context-3.schema.json",
    "agp.trust-policy-1.schema.json",
    "agp.trust-policy-2.schema.json",
    "reserved.schema.json",
}

DC3_SCHEMAS = {
    "agp.decision-context-3.schema.json",
    "agp.signature-statement-3.schema.json",
    "agp.signed-decision-context-3.schema.json",
}


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
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


def wheel_schema_bytes(wheel: Path) -> dict[str, bytes]:
    prefix = "trust_primitive_engine/schemas/"
    with ZipFile(wheel) as archive:
        return {
            name.removeprefix(prefix): archive.read(name)
            for name in archive.namelist()
            if name.startswith(prefix) and name.endswith(".schema.json")
        }


def main() -> int:
    passed = 0

    with tempfile.TemporaryDirectory(prefix="agp-tpe-package-") as raw:
        temp = Path(raw)
        dist = temp / "dist"
        env_dir = temp / "venv"
        run_dir = temp / "outside-repository"
        dist.mkdir()
        run_dir.mkdir()

        run([
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--wheel-dir",
            str(dist),
        ])

        wheels = sorted(dist.glob("agp_tpe-2.6.0-*.whl"))
        if len(wheels) != 1:
            raise AssertionError(
                f"expected one agp-tpe 2.6.0 wheel, found: {wheels}"
            )
        wheel = wheels[0]

        packaged_schemas = wheel_schema_bytes(wheel)
        missing = sorted(REQUIRED_SCHEMAS - set(packaged_schemas))
        unexpected = sorted(set(packaged_schemas) - REQUIRED_SCHEMAS)
        assert not missing, f"missing packaged schemas: {missing}"
        assert not unexpected, f"unexpected packaged schemas: {unexpected}"
        assert DC3_SCHEMAS <= set(packaged_schemas)
        print("PASS wheel schema inventory: 13/13 present")
        passed += 1

        for name, packaged in sorted(packaged_schemas.items()):
            authoritative = (AUTHORITATIVE_SCHEMAS / name).read_bytes()
            assert packaged == authoritative, (
                name,
                sha256(authoritative).hexdigest(),
                sha256(packaged).hexdigest(),
            )
        print("PASS wheel schema registry parity: byte-identical")
        passed += 1

        venv.EnvBuilder(with_pip=True).create(env_dir)
        python = (
            env_dir / "Scripts/python.exe"
            if os.name == "nt"
            else env_dir / "bin/python"
        )

        run([
            str(python),
            "-m",
            "pip",
            "install",
            str(wheel),
        ], cwd=run_dir)

        smoke = run([
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
        ], cwd=run_dir, capture=True)
        print(smoke.stdout, end="")
        print("PASS installed wheel public API")
        passed += 1

        validation_code = f"""
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from trust_primitive_engine import DEFAULT_SCHEMA_DIR

names = [
    "agp.decision-context-3.schema.json",
    "agp.signature-statement-3.schema.json",
    "agp.signed-decision-context-3.schema.json",
]
schemas = {{
    name: json.loads(
        (DEFAULT_SCHEMA_DIR / name).read_text(encoding="utf-8")
    )
    for name in names
}}
registry = Registry()
for schema in schemas.values():
    registry = registry.with_resource(
        schema["$id"],
        Resource.from_contents(schema),
    )

fixture = json.loads(
    Path({str(SIGNED_DC3_FIXTURE)!r}).read_text(encoding="utf-8")
)
Draft202012Validator(
    schemas["agp.signed-decision-context-3.schema.json"],
    registry=registry,
).validate(fixture)

print("INSTALLED_WHEEL_DC3_SCHEMA_VALIDATION_PASS")
"""
        validation = run(
            [str(python), "-c", validation_code],
            cwd=run_dir,
            capture=True,
        )
        print(validation.stdout, end="")
        print("PASS installed wheel Signed Decision Context 3 validation")
        passed += 1

        assert passed == 4, passed
        print(f"PASS built wheel: {wheel.name}")
        print("AGP TPE package installation and schema audit: 4/4 passed")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

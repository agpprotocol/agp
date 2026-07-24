#!/usr/bin/env python3
"""Generate the versioned AGP TPE 2.0 byte-stability corpus."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = (
    ROOT
    / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)
GOLDEN_DIR = ROOT / "trust_primitive_engine/fixtures/golden/v2"
DEFAULT_OUTPUT_DIR = (
    ROOT / "trust_primitive_engine/fixtures/byte_stability/v2"
)

VALID_FIXTURES = [
    "valid_required_signer.json",
    "valid_signer_threshold.json",
    "valid_global_thresholds.json",
    "valid_role_thresholds.json",
    "valid_constraints.json",
    "valid_cardinality.json",
]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def stable_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe_v2_byte_stability_generator",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate AGP TPE 2.0 byte-stability fixtures."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing generated corpus",
    )
    args = parser.parse_args()

    output_dir = args.output_dir
    manifest_path = output_dir / "manifest.json"

    if manifest_path.exists() and not args.force:
        parser.error(
            f"{manifest_path} already exists; use --force to regenerate"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    evaluator = load_evaluator()

    entries: list[dict[str, Any]] = []

    for fixture_name in VALID_FIXTURES:
        source_path = GOLDEN_DIR / fixture_name
        source_bytes = source_path.read_bytes()
        source_value = json.loads(source_bytes)

        validated_once = evaluator.validate_policy(source_value)
        validated_twice = evaluator.validate_policy(source_value)

        output_bytes = stable_json_bytes(validated_once)
        repeated_bytes = stable_json_bytes(validated_twice)

        if output_bytes != repeated_bytes:
            raise RuntimeError(
                f"non-deterministic validation output for {fixture_name}"
            )

        output_name = fixture_name.removesuffix(".json") + ".normalized.json"
        output_path = output_dir / output_name
        output_path.write_bytes(output_bytes)

        entries.append(
            {
                "source_fixture": fixture_name,
                "source_sha256": sha256_bytes(source_bytes),
                "normalized_fixture": output_name,
                "normalized_sha256": sha256_bytes(output_bytes),
                "normalized_size_bytes": len(output_bytes),
            }
        )
        print(
            f"WROTE {output_name:<48} "
            f"sha256={sha256_bytes(output_bytes)}"
        )

    manifest = {
        "format": "agp-tpe-v2-byte-stability",
        "format_version": 1,
        "policy_version": 2,
        "encoding": "UTF-8",
        "serialization": {
            "ensure_ascii": False,
            "separators": [",", ":"],
            "sort_keys": True,
            "trailing_newline": True,
        },
        "entries": entries,
    }

    manifest_path.write_bytes(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )

    print(
        "AGP TPE 2.0 byte-stability corpus generated: "
        f"{len(entries)} fixtures"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

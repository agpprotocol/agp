#!/usr/bin/env python3
"""Verify the versioned AGP TPE 2.0 byte-stability corpus."""

from __future__ import annotations

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
CORPUS_DIR = ROOT / "trust_primitive_engine/fixtures/byte_stability/v2"
MANIFEST_PATH = CORPUS_DIR / "manifest.json"


class TestFailure(Exception):
    pass


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
        "agp_tpe_v2_byte_stability_test",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise TestFailure(detail)


def main() -> int:
    manifest_bytes = MANIFEST_PATH.read_bytes()
    manifest = json.loads(manifest_bytes)

    require(
        manifest.get("format") == "agp-tpe-v2-byte-stability",
        "unexpected manifest format",
    )
    require(
        manifest.get("format_version") == 1,
        "unexpected manifest format version",
    )
    require(
        manifest.get("policy_version") == 2,
        "unexpected policy version",
    )

    entries = manifest.get("entries")
    require(isinstance(entries, list), "manifest entries must be an array")
    require(bool(entries), "manifest entries must not be empty")

    source_names: set[str] = set()
    normalized_names: set[str] = set()
    evaluator = load_evaluator()
    passed = 0

    for entry in entries:
        require(isinstance(entry, dict), "manifest entry must be an object")

        source_name = entry.get("source_fixture")
        normalized_name = entry.get("normalized_fixture")
        require(isinstance(source_name, str), "invalid source fixture name")
        require(
            isinstance(normalized_name, str),
            "invalid normalized fixture name",
        )
        require(
            source_name not in source_names,
            f"duplicate source fixture: {source_name}",
        )
        require(
            normalized_name not in normalized_names,
            f"duplicate normalized fixture: {normalized_name}",
        )
        source_names.add(source_name)
        normalized_names.add(normalized_name)

        source_path = GOLDEN_DIR / source_name
        normalized_path = CORPUS_DIR / normalized_name
        source_bytes = source_path.read_bytes()
        expected_bytes = normalized_path.read_bytes()

        require(
            sha256_bytes(source_bytes) == entry.get("source_sha256"),
            f"source digest mismatch: {source_name}",
        )
        require(
            sha256_bytes(expected_bytes) == entry.get("normalized_sha256"),
            f"normalized digest mismatch: {normalized_name}",
        )
        require(
            len(expected_bytes) == entry.get("normalized_size_bytes"),
            f"normalized size mismatch: {normalized_name}",
        )

        source_value = json.loads(source_bytes)
        first = stable_json_bytes(
            evaluator.validate_policy(source_value)
        )
        second = stable_json_bytes(
            evaluator.validate_policy(source_value)
        )

        require(
            first == second,
            f"repeated output differs: {source_name}",
        )
        require(
            first == expected_bytes,
            f"byte stability regression: {source_name}",
        )
        require(
            first.endswith(b"\n"),
            f"missing trailing newline: {normalized_name}",
        )
        require(
            b"\\r\\n" not in first,
            f"CRLF found in normalized output: {normalized_name}",
        )

        print(
            f"PASS  {source_name:<42} "
            f"bytes={len(first)} "
            f"sha256={sha256_bytes(first)}"
        )
        passed += 1

    actual_normalized = {
        path.name
        for path in CORPUS_DIR.glob("*.normalized.json")
    }
    require(
        actual_normalized == normalized_names,
        "manifest/files mismatch: "
        f"manifest={sorted(normalized_names)} "
        f"files={sorted(actual_normalized)}",
    )

    print(
        "AGP TPE 2.0 byte stability: "
        f"{passed}/{len(entries)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TestFailure,
    ) as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)

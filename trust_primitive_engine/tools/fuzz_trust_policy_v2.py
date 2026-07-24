#!/usr/bin/env python3
"""Deterministic structural fuzzing for AGP Trust Policy Engine 2.0."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
GOLDEN_DIR = ROOT / "trust_primitive_engine/fixtures/golden/v2"
DEFAULT_FAILURE_DIR = ROOT / "trust_primitive_engine/fuzz/failures"

VALID_FIXTURES = [
    "valid_required_signer.json",
    "valid_signer_threshold.json",
    "valid_global_thresholds.json",
    "valid_role_thresholds.json",
    "valid_constraints.json",
    "valid_cardinality.json",
]


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe_v2_structural_fuzzer",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def outcome(module: Any, value: Any) -> tuple[str, str]:
    expected_failure = getattr(module, "EvaluationFailure", None)

    try:
        normalized = module.validate_policy(copy.deepcopy(value))
    except Exception as exc:
        if expected_failure is not None and isinstance(exc, expected_failure):
            code = getattr(exc, "code", type(exc).__name__)
            return ("reject", f"{code}:{str(exc)}")
        raise

    return ("accept", stable_json(normalized))


def all_paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    paths = [prefix]
    if isinstance(value, dict):
        for key, child in value.items():
            paths.extend(all_paths(child, prefix + (key,)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(all_paths(child, prefix + (index,)))
    return paths


def get_at(value: Any, path: tuple[Any, ...]) -> Any:
    current = value
    for part in path:
        current = current[part]
    return current


def set_at(value: Any, path: tuple[Any, ...], replacement: Any) -> Any:
    if not path:
        return replacement

    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement
    return value


def delete_at(value: Any, path: tuple[Any, ...]) -> Any:
    if not path:
        return None

    current = value
    for part in path[:-1]:
        current = current[part]

    last = path[-1]
    if isinstance(current, dict):
        del current[last]
    elif isinstance(current, list):
        del current[last]
    return value


def random_scalar(rng: random.Random) -> Any:
    choices: list[Any] = [
        None,
        True,
        False,
        -1,
        0,
        1,
        2,
        2**53 - 1,
        2**53,
        "",
        "a",
        "é",
        "💥",
        "\x00",
        [],
        {},
    ]
    return copy.deepcopy(rng.choice(choices))


def mutate_once(source: Any, rng: random.Random) -> tuple[Any, str]:
    value = copy.deepcopy(source)
    paths = all_paths(value)
    path = rng.choice(paths)
    current = get_at(value, path) if path else value

    operations = ["replace", "delete", "duplicate", "reorder", "unknown-key"]
    operation = rng.choice(operations)

    if operation == "replace":
        return set_at(value, path, random_scalar(rng)), f"replace:{path!r}"

    if operation == "delete":
        if not path:
            return None, "delete:root"
        return delete_at(value, path), f"delete:{path!r}"

    if operation == "duplicate" and isinstance(current, list) and current:
        current.insert(rng.randrange(len(current) + 1), copy.deepcopy(rng.choice(current)))
        return value, f"duplicate-list-item:{path!r}"

    if operation == "reorder":
        if isinstance(current, list) and len(current) >= 2:
            rng.shuffle(current)
            return value, f"shuffle-list:{path!r}"
        if isinstance(current, dict) and len(current) >= 2:
            items = list(current.items())
            rng.shuffle(items)
            replacement = dict(items)
            return set_at(value, path, replacement), f"reorder-object:{path!r}"

    if operation == "unknown-key" and isinstance(current, dict):
        current[f"fuzz_unknown_{rng.randrange(1_000_000)}"] = random_scalar(rng)
        return value, f"unknown-key:{path!r}"

    return set_at(value, path, random_scalar(rng)), f"fallback-replace:{path!r}"


def persist_failure(
    directory: Path,
    *,
    campaign_seed: int,
    example_index: int,
    fixture_name: str,
    mutation: str,
    value: Any,
    detail: str,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "format": "agp-tpe-v2-fuzz-failure",
        "format_version": 1,
        "campaign_seed": campaign_seed,
        "example_index": example_index,
        "source_fixture": fixture_name,
        "mutation": mutation,
        "detail": detail,
        "value": value,
    }
    encoded = (json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n").encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    path = directory / f"failure-{campaign_seed}-{example_index}-{digest}.json"
    path.write_bytes(encoded)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run deterministic structural fuzzing against TPE 2.0."
    )
    parser.add_argument("--seed", type=int, default=20260723)
    parser.add_argument("--examples", type=int, default=5000)
    parser.add_argument("--mutations-per-example", type=int, default=1)
    parser.add_argument("--failure-dir", type=Path, default=DEFAULT_FAILURE_DIR)
    args = parser.parse_args()

    if args.examples < 1:
        parser.error("--examples must be at least 1")
    if args.mutations_per_example < 1:
        parser.error("--mutations-per-example must be at least 1")

    module = load_evaluator()
    fixtures = {
        name: json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))
        for name in VALID_FIXTURES
    }

    rng = random.Random(args.seed)
    accepted = 0
    rejected = 0

    for index in range(args.examples):
        fixture_name = rng.choice(VALID_FIXTURES)
        value: Any = fixtures[fixture_name]
        mutations: list[str] = []

        for _ in range(args.mutations_per_example):
            value, mutation = mutate_once(value, rng)
            mutations.append(mutation)

        try:
            first = outcome(module, value)
            second = outcome(module, value)
        except Exception as exc:
            path = persist_failure(
                args.failure_dir,
                campaign_seed=args.seed,
                example_index=index,
                fixture_name=fixture_name,
                mutation=" | ".join(mutations),
                value=value,
                detail=f"unexpected exception {type(exc).__name__}: {exc}",
            )
            print(f"FAIL unexpected exception; saved {path}", file=sys.stderr)
            return 1

        if first != second:
            path = persist_failure(
                args.failure_dir,
                campaign_seed=args.seed,
                example_index=index,
                fixture_name=fixture_name,
                mutation=" | ".join(mutations),
                value=value,
                detail=f"non-deterministic outcomes: {first!r} != {second!r}",
            )
            print(f"FAIL non-determinism; saved {path}", file=sys.stderr)
            return 1

        if first[0] == "accept":
            accepted += 1
        else:
            rejected += 1

    print(
        "AGP TPE 2.0 structural fuzzing: "
        f"{args.examples}/{args.examples} deterministic examples passed; "
        f"accepted={accepted} rejected={rejected} seed={args.seed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

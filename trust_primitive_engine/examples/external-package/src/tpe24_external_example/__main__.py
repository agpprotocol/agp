from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import Path
from typing import Any

import trust_primitive_engine
from trust_primitive_engine import evaluate_trust_policy


def load_json(name: str) -> Any:
    resource = importlib.resources.files(
        "tpe24_external_example.fixtures"
    ).joinpath(name)
    return json.loads(resource.read_text(encoding="utf-8"))


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def main() -> int:
    result = evaluate_trust_policy(
        signed_context=load_json("signed-context.json"),
        policy=load_json("root-policy.json"),
        keyring=load_json("keyring.json"),
        policy_set=load_json("policy-set.json"),
    )

    expected = importlib.resources.files(
        "tpe24_external_example.fixtures"
    ).joinpath("expected-result.sha256").read_text(
        encoding="ascii"
    ).strip()
    actual = hashlib.sha256(compact_json(result)).hexdigest()
    module_path = Path(trust_primitive_engine.__file__).resolve()

    assert result["status"] == "satisfied", result
    assert result["failure_codes"] == [], result
    assert actual == expected, (expected, actual)

    print(f"TPE_MODULE_PATH={module_path}")
    print(f"RESULT_STATUS={result['status']}")
    print(f"RESULT_SHA256={actual}")
    print("TPE_2_4_EXTERNAL_PACKAGE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

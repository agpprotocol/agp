from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import Path
from typing import Any

import trust_primitive_engine
from trust_primitive_engine import evaluate_trust_policy


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def resource_text(*parts: str) -> str:
    resource = importlib.resources.files(
        "tpe26_external_reproduction.fixtures"
    )
    for part in parts:
        resource = resource.joinpath(part)
    return resource.read_text(encoding="utf-8")


def load_json(*parts: str) -> Any:
    return json.loads(resource_text(*parts))


def main() -> int:
    manifest = load_json("manifest.json")
    module_path = Path(trust_primitive_engine.__file__).resolve()

    print(f"TPE_MODULE_PATH={module_path}")

    passed = 0
    for case in manifest["cases"]:
        name = case["name"]
        result = evaluate_trust_policy(
            signed_context=load_json(name, "signed-context.json"),
            policy=load_json(name, "root-policy.json"),
            keyring=load_json(name, "keyring.json"),
            policy_set=load_json(name, "policy-set.json"),
        )
        expected_digest = resource_text(
            name,
            "expected-result.sha256",
        ).strip()
        actual_digest = hashlib.sha256(compact_json(result)).hexdigest()

        assert result["status"] == case["expected_status"], result
        assert result["failure_codes"] == case["expected_failure_codes"], result
        assert actual_digest == expected_digest, (
            name,
            expected_digest,
            actual_digest,
        )
        assert actual_digest == case["expected_sha256"], (
            name,
            case["expected_sha256"],
            actual_digest,
        )

        print(f"CASE={name}")
        print(f"RESULT_STATUS={result['status']}")
        print(f"RESULT_SHA256={actual_digest}")
        passed += 1

    print(
        f"TPE_2_6_EXTERNAL_REPRODUCTION_PASS="
        f"{passed}/{len(manifest['cases'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

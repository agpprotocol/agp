#!/usr/bin/env python3
"""Focused CLI plumbing checks for TPE 2.3 policy sets."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_policy_set_cli",
        EVALUATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def primitive_policy(
    policy_id: str,
) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:alpha",
                "type": "required_signer",
                "signer_id": "authority:alpha",
            }
        ],
    }


def write_json(
    path: Path,
    value: Any,
) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def run_main(
    evaluator: Any,
    argv: list[str],
) -> tuple[int, str]:
    previous_argv = sys.argv

    try:
        sys.argv = argv
        output = io.StringIO()

        with redirect_stdout(output):
            return_code = evaluator.main()

        return return_code, output.getvalue()
    finally:
        sys.argv = previous_argv


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    with TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)

        input_path = temporary / "context.json"
        policy_path = temporary / "policy.json"
        policy_set_path = temporary / "policy-set.json"
        invalid_set_path = temporary / "invalid-policy-set.json"
        keyring_path = temporary / "keyring.json"

        root_policy = primitive_policy("policy:root")
        referenced_policy = primitive_policy(
            "policy:referenced"
        )

        write_json(input_path, {"placeholder": "context"})
        write_json(policy_path, root_policy)
        write_json(
            policy_set_path,
            [referenced_policy],
        )
        write_json(
            invalid_set_path,
            {"not": "an array"},
        )
        write_json(keyring_path, [])

        loaded_index = evaluator.load_policy_set_index(
            policy_set_path
        )

        if len(loaded_index) != 1:
            raise TestFailure(
                "valid_policy_set_load: wrong index size"
            )

        entry = loaded_index.resolve(
            "policy:referenced",
            1,
        )

        if entry is None:
            raise TestFailure(
                "valid_policy_set_load: entry missing"
            )

        print("PASS  valid_policy_set_load")
        passed += 1

        try:
            evaluator.load_policy_set_index(
                invalid_set_path
            )
        except evaluator.EvaluationFailure as exc:
            if exc.code != "INVALID_TRUST_POLICY_SET":
                raise TestFailure(
                    "invalid_policy_set: wrong code "
                    f"{exc.code}"
                ) from exc
        else:
            raise TestFailure(
                "invalid_policy_set: unexpectedly accepted"
            )

        print("PASS  invalid_policy_set_rejected")
        passed += 1

        captured_indexes: list[Any] = []

        def fake_load_json(
            path: Path,
            error_code: str,
        ) -> Any:
            del error_code

            if path == input_path:
                return {"placeholder": "context"}

            if path == policy_path:
                return root_policy

            raise TestFailure(
                f"unexpected load_json path: {path}"
            )

        def fake_load_keyring(path: Path) -> list[Any]:
            if path != keyring_path:
                raise TestFailure(
                    f"unexpected keyring path: {path}"
                )

            return []

        def fake_evaluate(
            signed_context: dict[str, Any],
            policy: dict[str, Any],
            keyring: list[dict[str, Any]],
            schema_dir: Path,
            *,
            policy_set_index: Any = None,
        ) -> dict[str, Any]:
            del signed_context
            del policy
            del keyring
            del schema_dir

            captured_indexes.append(policy_set_index)

            return {
                "status": "satisfied",
            }

        original_load_json = evaluator.load_json
        original_load_keyring = evaluator.load_keyring
        original_evaluate = evaluator.evaluate

        try:
            evaluator.load_json = fake_load_json
            evaluator.load_keyring = fake_load_keyring
            evaluator.evaluate = fake_evaluate

            return_code, output = run_main(
                evaluator,
                [
                    "evaluate_trust_policy_v2.py",
                    str(input_path),
                    "--policy",
                    str(policy_path),
                    "--keyring",
                    str(keyring_path),
                ],
            )
        finally:
            evaluator.load_json = original_load_json
            evaluator.load_keyring = original_load_keyring
            evaluator.evaluate = original_evaluate

        if return_code != 0:
            raise TestFailure(
                "cli_without_policy_set: nonzero exit"
            )

        if captured_indexes != [None]:
            raise TestFailure(
                "cli_without_policy_set: index was provided"
            )

        parsed_output = json.loads(output)

        if parsed_output["status"] != "satisfied":
            raise TestFailure(
                "cli_without_policy_set: wrong output"
            )

        print("PASS  cli_without_policy_set")
        passed += 1

        captured_indexes.clear()

        original_load_json = evaluator.load_json
        original_load_keyring = evaluator.load_keyring
        original_evaluate = evaluator.evaluate

        def fake_load_json_with_set(
            path: Path,
            error_code: str,
        ) -> Any:
            del error_code

            if path == input_path:
                return {"placeholder": "context"}

            if path == policy_path:
                return root_policy

            if path == policy_set_path:
                return [referenced_policy]

            raise TestFailure(
                f"unexpected load_json path: {path}"
            )

        try:
            evaluator.load_json = fake_load_json_with_set
            evaluator.load_keyring = fake_load_keyring
            evaluator.evaluate = fake_evaluate

            return_code, output = run_main(
                evaluator,
                [
                    "evaluate_trust_policy_v2.py",
                    str(input_path),
                    "--policy",
                    str(policy_path),
                    "--policy-set",
                    str(policy_set_path),
                    "--keyring",
                    str(keyring_path),
                ],
            )
        finally:
            evaluator.load_json = original_load_json
            evaluator.load_keyring = original_load_keyring
            evaluator.evaluate = original_evaluate

        if return_code != 0:
            raise TestFailure(
                "cli_with_policy_set: nonzero exit"
            )

        if len(captured_indexes) != 1:
            raise TestFailure(
                "cli_with_policy_set: evaluate not called"
            )

        provided_index = captured_indexes[0]

        if provided_index is None:
            raise TestFailure(
                "cli_with_policy_set: index missing"
            )

        if provided_index.resolve(
            "policy:referenced",
            1,
        ) is None:
            raise TestFailure(
                "cli_with_policy_set: wrong index"
            )

        parsed_output = json.loads(output)

        if parsed_output["status"] != "satisfied":
            raise TestFailure(
                "cli_with_policy_set: wrong output"
            )

        print("PASS  cli_with_policy_set")
        passed += 1

        first = evaluator.load_policy_set_index(
            policy_set_path
        )
        second = evaluator.load_policy_set_index(
            policy_set_path
        )

        if first.identities != second.identities:
            raise TestFailure(
                "deterministic_policy_set_load: differs"
            )

        print("PASS  deterministic_policy_set_load")
        passed += 1

    expected = 5

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        "TPE 2.3 policy-set CLI: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)

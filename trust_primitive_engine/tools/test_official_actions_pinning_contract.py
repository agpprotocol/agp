#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
EXPECTED_TOTAL = 9

EXPECTED = {
    "actions/checkout": {
        "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "comment": "# v7.0.1",
        "count": 9,
    },
    "actions/setup-go": {
        "sha": "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
        "comment": "# v7.0.0",
        "count": 5,
    },
    "actions/setup-python": {
        "sha": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "comment": "# v7.0.0",
        "count": 6,
    },
    "actions/upload-artifact": {
        "sha": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "comment": "# v7.0.1",
        "count": 2,
    },
}

REFERENCE_PATTERN = re.compile(
    r"uses:\s*(actions/(?:checkout|setup-go|setup-python|upload-artifact))"
    r"@([^\s#]+)(?:\s+(#\s*v[^\s]+))?"
)

FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def load_workflows() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml"))
    }


def main() -> int:
    workflows = load_workflows()
    combined = "\n".join(workflows.values())
    references = REFERENCE_PATTERN.findall(combined)

    grouped: dict[str, list[tuple[str, str]]] = {
        action: []
        for action in EXPECTED
    }

    for action, reference, comment in references:
        grouped[action].append((reference, comment))

    checks = [
        (
            "official setup action inventory is exact",
            set(grouped) == set(EXPECTED),
        ),
        (
            "all official setup references use full SHAs",
            all(
                FULL_SHA_PATTERN.fullmatch(reference)
                for values in grouped.values()
                for reference, _ in values
            ),
        ),
        (
            "checkout references match reviewed v7.0.1 commit",
            len(grouped["actions/checkout"])
            == EXPECTED["actions/checkout"]["count"]
            and all(
                reference == EXPECTED["actions/checkout"]["sha"]
                and comment == EXPECTED["actions/checkout"]["comment"]
                for reference, comment
                in grouped["actions/checkout"]
            ),
        ),
        (
            "setup-go references match reviewed v7.0.0 commit",
            len(grouped["actions/setup-go"])
            == EXPECTED["actions/setup-go"]["count"]
            and all(
                reference == EXPECTED["actions/setup-go"]["sha"]
                and comment == EXPECTED["actions/setup-go"]["comment"]
                for reference, comment
                in grouped["actions/setup-go"]
            ),
        ),
        (
            "setup-python references match reviewed v7.0.0 commit",
            len(grouped["actions/setup-python"])
            == EXPECTED["actions/setup-python"]["count"]
            and all(
                reference == EXPECTED["actions/setup-python"]["sha"]
                and comment == EXPECTED["actions/setup-python"]["comment"]
                for reference, comment
                in grouped["actions/setup-python"]
            ),
        ),
        (
            "upload-artifact references match reviewed v7.0.1 commit",
            len(grouped["actions/upload-artifact"])
            == EXPECTED["actions/upload-artifact"]["count"]
            and all(
                reference == EXPECTED["actions/upload-artifact"]["sha"]
                and comment == EXPECTED["actions/upload-artifact"]["comment"]
                for reference, comment
                in grouped["actions/upload-artifact"]
            ),
        ),
        (
            "moving official setup tags are absent",
            not any(
                marker in combined
                for marker in (
                    "actions/checkout@v",
                    "actions/setup-go@v",
                    "actions/setup-python@v",
                )
            ),
        ),
        (
            "reviewed official Actions reference count is twenty-two",
            sum(len(values) for values in grouped.values()) == 22,
        ),
        (
            "all reviewed version comments remain present",
            all(
                comment == EXPECTED[action]["comment"]
                for action, values in grouped.items()
                for _, comment in values
            ),
        ),
    ]

    passed = 0

    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(
        "AGP official Actions pinning contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )

    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())

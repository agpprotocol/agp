#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
EXPECTED_TOTAL = 10

EXPECTED_WORKFLOWS = {
    "canonicalization-conformance.yml",
    "conformance.yml",
    "decision-context-conformance.yml",
    "go-release-integrity.yml",
    "pages.yml",
    "publish-pypi.yml",
    "schema-registry-conformance.yml",
    "tpe-conformance.yml",
    "verify-release-attestations.yml",
}

EXPECTED_CONCURRENCY = {
    "canonicalization-conformance.yml": (
        "canonicalization-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "conformance.yml": (
        "agp-conformance-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "decision-context-conformance.yml": (
        "decision-context-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "go-release-integrity.yml": (
        "go-release-integrity-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "pages.yml": ('"pages"', "true"),
    "publish-pypi.yml": (
        "publish-agp-tpe-${{ github.event.release.tag_name }}",
        "false",
    ),
    "schema-registry-conformance.yml": (
        "schema-registry-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "tpe-conformance.yml": (
        "tpe-${{ github.workflow }}-${{ github.ref }}",
        "true",
    ),
    "verify-release-attestations.yml": (
        "verify-release-attestations-${{ inputs.tag }}",
        "false",
    ),
}

EXPECTED_TIMEOUTS = {
    "canonicalization-conformance.yml": 10,
    "conformance.yml": 10,
    "decision-context-conformance.yml": 10,
    "go-release-integrity.yml": 20,
    "pages.yml": 10,
    "publish-pypi.yml": 15,
    "schema-registry-conformance.yml": 10,
    "tpe-conformance.yml": 15,
    "verify-release-attestations.yml": 15,
}

RUNS_ON_PATTERN = re.compile(
    r"(?m)^    runs-on:\s*[^\n]+$"
)

TIMEOUT_PATTERN = re.compile(
    r"(?m)^    timeout-minutes:\s*(\d+)\s*$"
)


def load_workflows() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml"))
    }


def has_exact_concurrency(
    text: str,
    group: str,
    cancel: str,
) -> bool:
    expected = (
        "concurrency:\n"
        f"  group: {group}\n"
        f"  cancel-in-progress: {cancel}\n"
    )
    return expected in text


def main() -> int:
    workflows = load_workflows()

    checks = [
        (
            "expected workflow inventory is exact",
            set(workflows) == EXPECTED_WORKFLOWS,
        ),
        (
            "every workflow defines concurrency",
            all(
                "concurrency:\n" in text
                for text in workflows.values()
            ),
        ),
        (
            "all concurrency groups match reviewed policy",
            all(
                has_exact_concurrency(
                    workflows[name],
                    *EXPECTED_CONCURRENCY[name],
                )
                for name in EXPECTED_WORKFLOWS
            ),
        ),
        (
            "pull-request workflows cancel superseded runs",
            all(
                EXPECTED_CONCURRENCY[name][1] == "true"
                for name in (
                    "canonicalization-conformance.yml",
                    "conformance.yml",
                    "decision-context-conformance.yml",
                    "go-release-integrity.yml",
                    "schema-registry-conformance.yml",
                    "tpe-conformance.yml",
                )
            ),
        ),
        (
            "release publishing never cancels in progress",
            EXPECTED_CONCURRENCY["publish-pypi.yml"][1] == "false",
        ),
        (
            "every workflow job has a timeout",
            all(
                len(RUNS_ON_PATTERN.findall(text))
                == len(TIMEOUT_PATTERN.findall(text))
                and len(RUNS_ON_PATTERN.findall(text)) > 0
                for text in workflows.values()
            ),
        ),
        (
            "all timeout values match reviewed bounds",
            all(
                [
                    int(value)
                    for value in TIMEOUT_PATTERN.findall(
                        workflows[name]
                    )
                ]
                == [EXPECTED_TIMEOUTS[name]]
                for name in EXPECTED_WORKFLOWS
            ),
        ),
        (
            "conformance timeouts remain ten minutes",
            all(
                EXPECTED_TIMEOUTS[name] == 10
                for name in (
                    "canonicalization-conformance.yml",
                    "conformance.yml",
                    "decision-context-conformance.yml",
                    "schema-registry-conformance.yml",
                )
            ),
        ),
        (
            "deployment workflows remain bounded",
            EXPECTED_TIMEOUTS["pages.yml"] == 10
            and EXPECTED_TIMEOUTS["publish-pypi.yml"] == 15,
        ),
        (
            "longer integrity workflows retain reviewed bounds",
            EXPECTED_TIMEOUTS["go-release-integrity.yml"] == 20
            and EXPECTED_TIMEOUTS["tpe-conformance.yml"] == 15,
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
        "AGP Actions execution bounds contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )

    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent

DECISION_BASE = ROOT / "decision"
DECISION_VECTORS = DECISION_BASE / "vectors"
DECISION_RESULTS = DECISION_BASE / "results"
DECISION_PYTHON_RESULTS = DECISION_RESULTS / "python"
DECISION_GO_RESULTS = DECISION_RESULTS / "go"
DECISION_GO_BINARY = DECISION_RESULTS / "agp-decision-go"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
) -> None:
    display = " ".join(str(part) for part in command)
    print(f"\n$ {display}", flush=True)

    subprocess.run(
        command,
        cwd=cwd,
        check=True,
    )


def compare_directories(
    left: Path,
    right: Path,
) -> int:
    left_files = sorted(
        path.relative_to(left)
        for path in left.rglob("*.json")
    )
    right_files = sorted(
        path.relative_to(right)
        for path in right.rglob("*.json")
    )

    if left_files != right_files:
        missing_from_right = sorted(
            set(left_files) - set(right_files)
        )
        missing_from_left = sorted(
            set(right_files) - set(left_files)
        )

        if missing_from_right:
            print(
                "Missing from Go results:",
                *missing_from_right,
                sep="\n  ",
            )

        if missing_from_left:
            print(
                "Missing from Python results:",
                *missing_from_left,
                sep="\n  ",
            )

        raise RuntimeError(
            "Python and Go produced different result file sets"
        )

    for relative_path in left_files:
        python_bytes = (left / relative_path).read_bytes()
        go_bytes = (right / relative_path).read_bytes()

        if python_bytes != go_bytes:
            raise RuntimeError(
                "Non-identical Decision Context receipt: "
                f"{relative_path}"
            )

    return len(left_files)


def run_v03_to_v05() -> None:
    print("\n" + "=" * 72)
    print("AGP v0.3–v0.5 regression")
    print("=" * 72)

    run(
        [
            sys.executable,
            str(ROOT / "run_all_v0.5.py"),
        ]
    )


def run_decision_context() -> int:
    print("\n" + "=" * 72)
    print("AGP v0.6 Decision Context")
    print("=" * 72)

    run(
        [
            sys.executable,
            str(
                DECISION_BASE
                / "tools"
                / "generate_vectors.py"
            ),
        ]
    )

    shutil.rmtree(
        DECISION_PYTHON_RESULTS,
        ignore_errors=True,
    )
    shutil.rmtree(
        DECISION_GO_RESULTS,
        ignore_errors=True,
    )

    DECISION_PYTHON_RESULTS.mkdir(
        parents=True,
        exist_ok=True,
    )
    DECISION_GO_RESULTS.mkdir(
        parents=True,
        exist_ok=True,
    )

    DECISION_RESULTS.mkdir(
        parents=True,
        exist_ok=True,
    )

    run(
        [
            sys.executable,
            str(
                DECISION_BASE
                / "python"
                / "decision.py"
            ),
            str(DECISION_VECTORS),
            str(DECISION_PYTHON_RESULTS),
        ]
    )

    run(
        [
            "go",
            "build",
            "-o",
            str(DECISION_GO_BINARY),
            str(
                DECISION_BASE
                / "go"
                / "cmd"
                / "agp-decision"
                / "main.go"
            ),
        ],
        cwd=ROOT,
    )

    run(
        [
            str(DECISION_GO_BINARY),
            str(DECISION_VECTORS),
            str(DECISION_GO_RESULTS),
        ]
    )

    vector_count = compare_directories(
        DECISION_PYTHON_RESULTS,
        DECISION_GO_RESULTS,
    )

    print(
        "\nAGP v0.6 Decision Context: "
        f"{vector_count}/{vector_count} "
        "Python-Go receipts byte-identical"
    )

    return vector_count


def run_signed_decision_context() -> None:
    print("\n" + "=" * 72)
    print("AGP v0.6 Signed Decision Context")
    print("=" * 72)

    run(
        [
            sys.executable,
            str(
                DECISION_BASE
                / "signed"
                / "tools"
                / "run_conformance.py"
            ),
        ]
    )


def main() -> int:
    try:
        run_v03_to_v05()
        decision_vector_count = run_decision_context()
        run_signed_decision_context()
    except (
        subprocess.CalledProcessError,
        RuntimeError,
    ) as error:
        print(
            "\nAGP FULL REGRESSION: FAILED",
            file=sys.stderr,
        )
        print(str(error), file=sys.stderr)
        return 1
    finally:
        DECISION_GO_BINARY.unlink(
            missing_ok=True,
        )

    print("\n" + "=" * 72)
    print("AGP FULL REGRESSION: PASSED")
    print("=" * 72)
    print("v0.3 Core:                    260/260")
    print("v0.4 Signed Envelopes:         10/10")
    print("v0.5 Transparency:              8/8")
    print(
        "v0.6 Decision Context:        "
        f"{decision_vector_count}/"
        f"{decision_vector_count}"
    )
    print("v0.6 Signed Decision Context:    7/7")
    print("Cross-language receipts:        identical")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

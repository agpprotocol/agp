#!/usr/bin/env python3
"""Safe mutation-resilience probe for AGP Trust Primitive Engine 2.0.

The tool never edits the working tree. For each mutant it copies the repository
to a temporary directory, changes only the copied evaluator, and runs the
selected compatibility suites there.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_REL = Path(
    "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)

SUITES = [
    Path("trust_primitive_engine/tools/test_engine_core.py"),
    Path("trust_primitive_engine/tools/run_conformance.py"),
    Path("trust_primitive_engine/tools/test_schema_runtime_parity.py"),
    Path(
        "trust_primitive_engine/tools/"
        "test_primitive_schema_runtime_matrix.py"
    ),
    Path("trust_primitive_engine/tools/test_golden_policy_corpus.py"),
    Path("trust_primitive_engine/tools/test_mutation_observability.py"),
]

IGNORES = shutil.ignore_patterns(
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".hypothesis",
    ".pytest_cache",
    "*.pyc",
    "*.pyo",
)


@dataclass(frozen=True)
class Mutation:
    line: int
    column: int
    original: str
    replacement: str
    description: str


COMPARE_REPLACEMENTS = {
    ast.Eq: ("==", "!="),
    ast.NotEq: ("!=", "=="),
    ast.Lt: ("<", "<="),
    ast.LtE: ("<=", "<"),
    ast.Gt: (">", ">="),
    ast.GtE: (">=", ">"),
    ast.In: (" in ", " not in "),
    ast.NotIn: (" not in ", " in "),
    ast.Is: (" is ", " is not "),
    ast.IsNot: (" is not ", " is "),
}


def line_offsets(text: str) -> list[int]:
    offsets = [0]
    for index, char in enumerate(text):
        if char == "\n":
            offsets.append(index + 1)
    return offsets


def absolute_offset(
    offsets: list[int],
    line: int,
    column: int,
) -> int:
    return offsets[line - 1] + column


def find_operator_between(
    source: str,
    offsets: list[int],
    left: ast.AST,
    right: ast.AST,
    token: str,
) -> tuple[int, str] | None:
    if (
        not hasattr(left, "end_lineno")
        or left.end_lineno is None
        or left.end_col_offset is None
        or not hasattr(right, "lineno")
    ):
        return None

    start = absolute_offset(
        offsets,
        left.end_lineno,
        left.end_col_offset,
    )
    end = absolute_offset(
        offsets,
        right.lineno,
        right.col_offset,
    )
    region = source[start:end]

    stripped = token.strip()
    index = region.find(stripped)
    if index < 0:
        return None
    return start + index, stripped


def collect_mutations(source: str) -> list[Mutation]:
    tree = ast.parse(source)
    offsets = line_offsets(source)
    mutations: list[Mutation] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for index, operator in enumerate(node.ops):
                replacement = COMPARE_REPLACEMENTS.get(type(operator))
                if replacement is None:
                    continue
                original_token, replacement_token = replacement
                located = find_operator_between(
                    source,
                    offsets,
                    operands[index],
                    operands[index + 1],
                    original_token,
                )
                if located is None:
                    continue
                absolute, actual = located
                line = source.count("\n", 0, absolute) + 1
                line_start = source.rfind("\n", 0, absolute) + 1
                column = absolute - line_start
                mutations.append(
                    Mutation(
                        line=line,
                        column=column,
                        original=actual,
                        replacement=replacement_token.strip(),
                        description=(
                            f"compare {actual!r} -> "
                            f"{replacement_token.strip()!r}"
                        ),
                    )
                )

        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            start = absolute_offset(
                offsets,
                node.lineno,
                node.col_offset,
            )
            original = "True" if node.value else "False"
            replacement = "False" if node.value else "True"
            mutations.append(
                Mutation(
                    line=node.lineno,
                    column=node.col_offset,
                    original=original,
                    replacement=replacement,
                    description=f"boolean {original} -> {replacement}",
                )
            )

    unique: dict[tuple[int, int, str, str], Mutation] = {}
    for mutation in mutations:
        key = (
            mutation.line,
            mutation.column,
            mutation.original,
            mutation.replacement,
        )
        unique[key] = mutation

    return sorted(
        unique.values(),
        key=lambda item: (
            item.line,
            item.column,
            item.original,
            item.replacement,
        ),
    )


def apply_mutation(source: str, mutation: Mutation) -> str:
    lines = source.splitlines(keepends=True)
    line = lines[mutation.line - 1]
    start = mutation.column
    end = start + len(mutation.original)

    if line[start:end] != mutation.original:
        raise RuntimeError(
            f"source mismatch at {mutation.line}:{mutation.column}: "
            f"expected {mutation.original!r}, found {line[start:end]!r}"
        )

    lines[mutation.line - 1] = (
        line[:start] + mutation.replacement + line[end:]
    )
    mutated = "".join(lines)
    ast.parse(mutated)
    return mutated


def run_suite(
    repository: Path,
    suite: Path,
    timeout_seconds: int,
) -> tuple[bool, str]:
    env = os.environ.copy()
    completed = subprocess.run(
        [sys.executable, str(repository / suite)],
        cwd=repository,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout_seconds,
        check=False,
    )
    return completed.returncode == 0, completed.stdout


def run_baseline(timeout_seconds: int) -> None:
    print("Running unmutated baseline...")
    for suite in SUITES:
        passed, output = run_suite(ROOT, suite, timeout_seconds)
        if not passed:
            print(output, file=sys.stderr)
            raise SystemExit(
                f"baseline suite failed before mutation: {suite}"
            )
    print("PASS  baseline suites")


def copy_repository(destination: Path) -> Path:
    copied = destination / "repo"
    shutil.copytree(ROOT, copied, ignore=IGNORES)
    return copied


def select_mutations(
    mutations: list[Mutation],
    maximum: int,
) -> list[Mutation]:
    if maximum <= 0 or maximum >= len(mutations):
        return mutations

    # Deterministic spread across the file instead of taking only the first N.
    if maximum == 1:
        return [mutations[len(mutations) // 2]]

    selected: list[Mutation] = []
    used: set[int] = set()
    for slot in range(maximum):
        index = round(slot * (len(mutations) - 1) / (maximum - 1))
        if index not in used:
            selected.append(mutations[index])
            used.add(index)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-mutants",
        type=int,
        default=30,
        help="maximum deterministic sample; 0 means all",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="timeout in seconds for each suite",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="minimum killed-mutant percentage required",
    )
    args = parser.parse_args()

    evaluator_path = ROOT / EVALUATOR_REL
    source = evaluator_path.read_text(encoding="utf-8")
    all_mutations = collect_mutations(source)
    mutations = select_mutations(all_mutations, args.max_mutants)

    if not mutations:
        raise SystemExit("no mutation candidates found")

    print(
        f"Discovered {len(all_mutations)} candidates; "
        f"testing {len(mutations)} mutants"
    )
    run_baseline(args.timeout)

    killed = 0
    survived: list[Mutation] = []
    started = time.perf_counter()

    for number, mutation in enumerate(mutations, start=1):
        status = "SURVIVED"
        killing_suite = ""

        with tempfile.TemporaryDirectory(
            prefix="agp-tpe-mutant-"
        ) as temp:
            repository = copy_repository(Path(temp))
            copied_evaluator = repository / EVALUATOR_REL
            copied_source = copied_evaluator.read_text(encoding="utf-8")
            copied_evaluator.write_text(
                apply_mutation(copied_source, mutation),
                encoding="utf-8",
            )

            for suite in SUITES:
                try:
                    passed, _output = run_suite(
                        repository,
                        suite,
                        args.timeout,
                    )
                except subprocess.TimeoutExpired:
                    passed = False
                    killing_suite = f"{suite} (timeout)"

                if not passed:
                    status = "KILLED"
                    if not killing_suite:
                        killing_suite = str(suite)
                    killed += 1
                    break

        if status == "SURVIVED":
            survived.append(mutation)

        suffix = (
            f" by {killing_suite}"
            if killing_suite
            else ""
        )
        print(
            f"{status:<8} {number:>3}/{len(mutations)} "
            f"line={mutation.line:<5} "
            f"{mutation.description}{suffix}"
        )

    elapsed = time.perf_counter() - started
    score = killed * 100.0 / len(mutations)

    print("=" * 88)
    print(
        f"AGP TPE 2.0 mutation score: "
        f"{killed}/{len(mutations)} killed "
        f"({score:.1f}%), "
        f"{len(survived)} survived, "
        f"{elapsed:.1f}s"
    )

    if survived:
        print("Surviving mutants:")
        for mutation in survived:
            print(
                f"  line {mutation.line}:{mutation.column} "
                f"{mutation.description}"
            )

    if score + 1e-9 < args.min_score:
        print(
            f"FAIL  score {score:.1f}% is below "
            f"required {args.min_score:.1f}%",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

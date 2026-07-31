#!/usr/bin/env python3
"""Recover canonical candidate evidence for an exact preexisting release tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def run(
    command: list[str],
    *,
    cwd: Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"{' '.join(command)} failed: {detail}"
        )
    return completed


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package_identity(source_dir: Path) -> tuple[str, str]:
    import tomllib

    payload = tomllib.loads(
        (source_dir / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    project = payload.get("project")
    if not isinstance(project, dict):
        raise RuntimeError("pyproject project table is missing")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not name:
        raise RuntimeError("package name is missing")
    if not isinstance(version, str) or not version:
        raise RuntimeError("package version is missing")
    return name, version


def require_clean_tracked_tree(source_dir: Path) -> None:
    result = run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=source_dir,
    )
    if result.stdout.strip():
        raise RuntimeError("tracked source tree is not clean")


def require_exact_head(
    source_dir: Path,
    source_commit: str,
) -> None:
    head = run(
        ["git", "rev-parse", "HEAD"],
        cwd=source_dir,
    ).stdout.strip()
    if head != source_commit:
        raise RuntimeError(
            "source worktree HEAD does not match source commit"
        )


def require_local_annotated_tag(
    source_dir: Path,
    tag: str,
    source_commit: str,
) -> tuple[str, str]:
    ref = f"refs/tags/{tag}"
    tag_type = run(
        ["git", "cat-file", "-t", ref],
        cwd=source_dir,
    ).stdout.strip()
    if tag_type != "tag":
        raise RuntimeError("local release tag is not annotated")

    tag_object = run(
        ["git", "rev-parse", ref],
        cwd=source_dir,
    ).stdout.strip()
    peeled = run(
        ["git", "rev-parse", f"{ref}^{{}}"],
        cwd=source_dir,
    ).stdout.strip()
    if peeled != source_commit:
        raise RuntimeError(
            "local release tag does not peel to source commit"
        )
    return tag_object, peeled


def require_remote_tag(
    source_dir: Path,
    remote: str,
    tag: str,
    local_object: str,
    source_commit: str,
) -> None:
    result = run(
        [
            "git",
            "ls-remote",
            "--tags",
            remote,
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        ],
        cwd=source_dir,
    )
    refs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        value, ref = line.split("\t", 1)
        refs[ref] = value

    if refs.get(f"refs/tags/{tag}") != local_object:
        raise RuntimeError(
            "remote annotated tag object does not match local tag"
        )
    if refs.get(f"refs/tags/{tag}^{{}}") != source_commit:
        raise RuntimeError(
            "remote release tag does not peel to source commit"
        )


def require_release_absent(
    source_dir: Path,
    repository: str,
    tag: str,
) -> None:
    result = run(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            repository,
            "--json",
            "tagName",
        ],
        cwd=source_dir,
        check=False,
    )
    if result.returncode == 0:
        raise RuntimeError(
            f"GitHub Release already exists: {tag}"
        )
    combined = (
        result.stdout + "\n" + result.stderr
    ).lower()
    if "release not found" not in combined:
        raise RuntimeError(
            "unable to prove GitHub Release absence"
        )


def require_pypi_absent(
    package_name: str,
    version: str,
    *,
    endpoint: str,
) -> None:
    url = endpoint.format(package=package_name)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"PyPI lookup failed with HTTP {exc.code}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"PyPI lookup failed: {exc}"
        ) from exc

    releases = payload.get("releases")
    if not isinstance(releases, dict):
        raise RuntimeError("PyPI releases map is missing")
    if version in releases:
        raise RuntimeError(
            f"candidate version already exists on PyPI: {version}"
        )


def run_validation(
    source_dir: Path,
    *,
    expected_total: int,
    expected_runner_sha256: str,
) -> tuple[int, str, str]:
    runner_path = (
        source_dir
        / "trust_primitive_engine/tools/run_all_tests.py"
    )
    runner_raw = runner_path.read_bytes()
    runner_sha256 = sha256_bytes(runner_raw)
    if runner_sha256 != expected_runner_sha256:
        raise RuntimeError(
            "historical validation runner SHA-256 mismatch"
        )

    result = run(
        [sys.executable, str(runner_path)],
        cwd=source_dir,
    )
    marker = re.compile(
        r"AGP TPE 2[.]6 development validation: "
        r"([0-9]+)/([0-9]+) passed"
    )
    matches = marker.findall(result.stdout)
    if not matches:
        raise RuntimeError(
            "global validation summary was not found"
        )
    passed, total = map(int, matches[-1])
    if passed != total:
        raise RuntimeError(
            "global validation did not fully pass"
        )
    if total != expected_total:
        raise RuntimeError(
            f"unexpected historical validation total: {total}"
        )
    return total, result.stdout, runner_sha256


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recover canonical release-candidate evidence for an "
            "exact existing annotated tag without mutating GitHub, "
            "PyPI, or Git."
        )
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument(
        "--expected-validation-total",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--expected-validation-runner-sha256",
        required=True,
    )
    parser.add_argument(
        "--pypi-endpoint",
        default="https://pypi.org/pypi/{package}/json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    tag = f"tpe-v{args.version}"

    try:
        if GIT_OBJECT_ID.fullmatch(args.source_commit) is None:
            raise RuntimeError(
                "source commit must be a full lowercase Git "
                "object identifier"
            )

        require_clean_tracked_tree(source_dir)
        require_exact_head(source_dir, args.source_commit)

        package_name, package_version = package_identity(
            source_dir
        )
        if package_version != args.version:
            raise RuntimeError(
                "package version does not match requested version"
            )

        tag_object, peeled = require_local_annotated_tag(
            source_dir,
            tag,
            args.source_commit,
        )
        require_remote_tag(
            source_dir,
            args.remote,
            tag,
            tag_object,
            args.source_commit,
        )
        require_release_absent(
            source_dir,
            args.repository,
            tag,
        )
        require_pypi_absent(
            package_name,
            args.version,
            endpoint=args.pypi_endpoint,
        )

        if args.expected_validation_total <= 0:
            raise RuntimeError(
                "expected validation total must be positive"
            )
        if (
            SHA256.fullmatch(
                args.expected_validation_runner_sha256
            )
            is None
        ):
            raise RuntimeError(
                "expected validation runner SHA-256 is invalid"
            )

        (
            validation_total,
            validation_output,
            validation_runner_sha256,
        ) = run_validation(
            source_dir,
            expected_total=args.expected_validation_total,
            expected_runner_sha256=(
                args.expected_validation_runner_sha256
            ),
        )

        candidate = {
            "format": "agp-tpe-release-candidate-v1",
            "package_name": package_name,
            "package_version": args.version,
            "release_tag": tag,
            "source_commit": args.source_commit,
            "source_branch": "detached-tag-recovery",
            "validation_total": validation_total,
            "validation_status": "passed",
            "local_tag_available": True,
            "remote_tag_available": True,
            "pypi_version_available": True,
            "creates_tag": False,
            "creates_github_release": False,
            "publishes_to_pypi": False,
        }
        candidate_raw = canonical_bytes(candidate)
        candidate_digest = sha256_bytes(candidate_raw)

        recovery = {
            "format": (
                "agp-tpe-release-candidate-recovery-v1"
            ),
            "candidate_sha256": candidate_digest,
            "repository": args.repository,
            "release_tag": tag,
            "source_commit": args.source_commit,
            "local_tag_object": tag_object,
            "local_tag_peeled_commit": peeled,
            "remote_tag_object_verified": True,
            "remote_tag_peeled_commit_verified": True,
            "github_release_absent": True,
            "pypi_version_absent": True,
            "validation_total": validation_total,
            "validation_status": "passed",
            "validation_runner_sha256": (
                validation_runner_sha256
            ),
            "validation_baseline_source": (
                "explicit-historical-tag-runner"
            ),
            "recovered_at": datetime.now(
                timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "mutates_git": False,
            "mutates_github_release": False,
            "publishes_to_pypi": False,
            "creates_authorization": False,
        }

        output_dir.mkdir(parents=True, exist_ok=False)
        candidate_path = output_dir / "release-candidate.json"
        recovery_path = (
            output_dir / "release-candidate-recovery.json"
        )
        validation_path = output_dir / "validation.log"

        candidate_path.write_bytes(candidate_raw)
        recovery_path.write_bytes(canonical_bytes(recovery))
        validation_path.write_text(
            validation_output,
            encoding="utf-8",
        )
    except (
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"RECOVERED_RELEASE_TAG={tag}")
    print(f"RECOVERED_SOURCE_COMMIT={args.source_commit}")
    print(f"RECOVERED_TAG_OBJECT={tag_object}")
    print(f"RECOVERED_CANDIDATE_SHA256={candidate_digest}")
    print(f"RECOVERED_VALIDATION_TOTAL={validation_total}")
    print(
        "RECOVERED_VALIDATION_RUNNER_SHA256="
        f"{validation_runner_sha256}"
    )
    print(f"CANDIDATE_REPORT={candidate_path}")
    print(f"RECOVERY_REPORT={recovery_path}")
    print("TAG_MUTATION_EXECUTED=no")
    print("RELEASE_MUTATION_EXECUTED=no")
    print("PYPI_MUTATION_EXECUTED=no")
    print("AUTHORIZATION_CREATED=no")
    print("AGP_PREEXISTING_CANDIDATE_RECOVERY_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

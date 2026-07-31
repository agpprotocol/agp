#!/usr/bin/env python3
"""Prepare deterministic release-candidate evidence without creating a tag."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Sequence


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


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
            f"command failed ({completed.returncode}): "
            f"{' '.join(command)}: {detail}"
        )
    return completed


def load_project(source_dir: Path) -> tuple[str, str]:
    payload = tomllib.loads(
        (source_dir / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = payload["project"]
    return str(project["name"]), str(project["version"])


def require_clean_tracked_tree(source_dir: Path) -> None:
    for command in (
        ["git", "diff", "--quiet"],
        ["git", "diff", "--cached", "--quiet"],
    ):
        completed = run(command, cwd=source_dir, check=False)
        if completed.returncode != 0:
            raise RuntimeError(
                "tracked worktree or index is not clean"
            )


def require_tag_available(
    source_dir: Path,
    tag: str,
    remote: str,
) -> None:
    local = run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"],
        cwd=source_dir,
        check=False,
    )
    if local.returncode == 0:
        raise RuntimeError(f"local release tag already exists: {tag}")
    if local.returncode not in (0, 1):
        raise RuntimeError(f"unable to inspect local tag: {tag}")

    remote_result = run(
        ["git", "ls-remote", "--tags", remote, f"refs/tags/{tag}"],
        cwd=source_dir,
    )
    if remote_result.stdout.strip():
        raise RuntimeError(f"remote release tag already exists: {tag}")


def require_pypi_version_available(
    *,
    base_url: str,
    package_name: str,
    package_version: str,
    timeout: float,
) -> None:
    name = urllib.parse.quote(package_name, safe="")
    version = urllib.parse.quote(package_version, safe="")
    url = f"{base_url.rstrip('/')}/{name}/{version}/json"

    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return
        raise RuntimeError(
            f"PyPI lookup failed with HTTP {exc.code}: {url}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"PyPI lookup failed: {exc}") from exc

    published = payload.get("info", {}).get("version", package_version)
    raise RuntimeError(
        "candidate version already exists on PyPI: "
        f"{package_name}=={published}"
    )


def run_validation(
    source_dir: Path,
) -> tuple[int, str]:
    completed = run(
        [
            sys.executable,
            "trust_primitive_engine/tools/run_all_tests.py",
        ],
        cwd=source_dir,
    )
    pattern = re.compile(
        r"AGP TPE 2\.6 development validation: "
        r"([0-9]+)/\1 passed"
    )
    match = pattern.search(completed.stdout)
    if match is None:
        raise RuntimeError(
            "complete validation success marker was not found"
        )
    return int(match.group(1)), completed.stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a new package version and write deterministic "
            "release-candidate evidence without creating tags or releases."
        )
    )
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("."),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
    )
    parser.add_argument("--expected-package", default="agp-tpe")
    parser.add_argument("--remote", default="origin")
    parser.add_argument(
        "--pypi-base-url",
        default="https://pypi.org/pypi",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()

    try:
        if SEMVER.fullmatch(args.version) is None:
            raise RuntimeError(
                "candidate version must be stable SemVer X.Y.Z"
            )

        package_name, package_version = load_project(source_dir)
        if package_name != args.expected_package:
            raise RuntimeError(
                f"unexpected package name: {package_name!r}"
            )
        if package_version != args.version:
            raise RuntimeError(
                "candidate version does not match pyproject.toml: "
                f"{args.version!r} != {package_version!r}"
            )

        tag = f"tpe-v{args.version}"
        require_clean_tracked_tree(source_dir)
        require_tag_available(source_dir, tag, args.remote)
        require_pypi_version_available(
            base_url=args.pypi_base_url,
            package_name=package_name,
            package_version=package_version,
            timeout=args.timeout,
        )

        source_commit = run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_dir,
        ).stdout.strip()
        branch = run(
            ["git", "branch", "--show-current"],
            cwd=source_dir,
        ).stdout.strip()
        validation_total, validation_output = run_validation(source_dir)

        output_dir.mkdir(parents=True, exist_ok=True)
        report = {
            "format": "agp-tpe-release-candidate-v1",
            "package_name": package_name,
            "package_version": package_version,
            "release_tag": tag,
            "source_commit": source_commit,
            "source_branch": branch,
            "validation_total": validation_total,
            "validation_status": "passed",
            "local_tag_available": True,
            "remote_tag_available": True,
            "pypi_version_available": True,
            "creates_tag": False,
            "creates_github_release": False,
            "publishes_to_pypi": False,
        }

        report_path = output_dir / "release-candidate.json"
        summary_path = output_dir / "release-candidate.md"
        validation_path = output_dir / "validation.log"

        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary_path.write_text(
            "\n".join(
                [
                    "# AGP TPE release candidate",
                    "",
                    f"- Package: `{package_name}`",
                    f"- Version: `{package_version}`",
                    f"- Candidate tag: `{tag}`",
                    f"- Source commit: `{source_commit}`",
                    f"- Source branch: `{branch}`",
                    (
                        "- Complete validation: "
                        f"`{validation_total}/{validation_total} passed`"
                    ),
                    "- Local tag available: `yes`",
                    "- Remote tag available: `yes`",
                    "- PyPI version available: `yes`",
                    "- Tag created: `no`",
                    "- GitHub Release created: `no`",
                    "- PyPI publication performed: `no`",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        validation_path.write_text(validation_output, encoding="utf-8")
    except (
        KeyError,
        OSError,
        RuntimeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"RELEASE_CANDIDATE_REPORT={report_path}")
    print(f"RELEASE_CANDIDATE_SUMMARY={summary_path}")
    print(f"RELEASE_CANDIDATE_VALIDATION={validation_path}")
    print("AGP_RELEASE_CANDIDATE_PREPARATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

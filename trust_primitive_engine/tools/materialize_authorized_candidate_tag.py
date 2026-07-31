#!/usr/bin/env python3
"""Create only a local annotated tag from bound candidate evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence


AUTH_STATEMENT = (
    "I authorize creation of the local annotated candidate tag."
)
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)


def run_git(
    source_dir: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", "-C", str(source_dir), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"git {' '.join(args)} failed: {detail}"
        )
    return completed


def load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return payload, raw


def require_clean_tracked_tree(source_dir: Path) -> None:
    for args in (
        ("diff", "--quiet"),
        ("diff", "--cached", "--quiet"),
    ):
        completed = run_git(
            source_dir,
            *args,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "tracked worktree or index is not clean"
            )


def require_candidate(candidate: dict[str, Any]) -> None:
    expected = {
        "format": "agp-tpe-release-candidate-v1",
        "package_name": "agp-tpe",
        "validation_status": "passed",
        "local_tag_available": True,
        "remote_tag_available": True,
        "pypi_version_available": True,
        "creates_tag": False,
        "creates_github_release": False,
        "publishes_to_pypi": False,
    }
    for key, value in expected.items():
        if candidate.get(key) != value:
            raise RuntimeError(
                f"candidate field mismatch: {key}"
            )

    version = candidate.get("package_version")
    tag = candidate.get("release_tag")
    if not isinstance(version, str) or tag != f"tpe-v{version}":
        raise RuntimeError(
            "candidate tag does not match candidate version"
        )

    total = candidate.get("validation_total")
    if not isinstance(total, int) or total <= 0:
        raise RuntimeError(
            "candidate validation total is invalid"
        )


def require_authorization(
    authorization: dict[str, Any],
    *,
    candidate: dict[str, Any],
    candidate_digest: str,
) -> None:
    expected = {
        "format": "agp-tpe-release-authorization-v1",
        "decision": "authorize-local-annotated-tag",
        "candidate_sha256": candidate_digest,
        "release_tag": candidate["release_tag"],
        "source_commit": candidate["source_commit"],
        "statement": AUTH_STATEMENT,
    }
    for key, value in expected.items():
        if authorization.get(key) != value:
            raise RuntimeError(
                f"authorization field mismatch: {key}"
            )

    authorized_by = authorization.get("authorized_by")
    if (
        not isinstance(authorized_by, str)
        or not authorized_by.strip()
    ):
        raise RuntimeError("authorization identity is missing")

    authorized_at = authorization.get("authorized_at")
    if (
        not isinstance(authorized_at, str)
        or RFC3339_UTC.fullmatch(authorized_at) is None
    ):
        raise RuntimeError(
            "authorization time must be RFC3339 UTC"
        )
    datetime.strptime(authorized_at, "%Y-%m-%dT%H:%M:%SZ")


def require_source_alignment(
    source_dir: Path,
    candidate: dict[str, Any],
) -> None:
    head = run_git(
        source_dir,
        "rev-parse",
        "HEAD",
    ).stdout.strip()
    if head != candidate["source_commit"]:
        raise RuntimeError(
            "current HEAD does not match candidate source commit"
        )

    project = tomllib.loads(
        (source_dir / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )["project"]
    if project["name"] != candidate["package_name"]:
        raise RuntimeError(
            "current package name does not match candidate"
        )
    if project["version"] != candidate["package_version"]:
        raise RuntimeError(
            "current package version does not match candidate"
        )


def require_tag_absent(
    source_dir: Path,
    tag: str,
    remote: str,
) -> None:
    local = run_git(
        source_dir,
        "show-ref",
        "--verify",
        "--quiet",
        f"refs/tags/{tag}",
        check=False,
    )
    if local.returncode == 0:
        raise RuntimeError(
            f"local release tag already exists: {tag}"
        )
    if local.returncode != 1:
        raise RuntimeError(
            f"unable to inspect local release tag: {tag}"
        )

    remote_result = run_git(
        source_dir,
        "ls-remote",
        "--tags",
        remote,
        f"refs/tags/{tag}",
    )
    if remote_result.stdout.strip():
        raise RuntimeError(
            f"remote release tag already exists: {tag}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate bound candidate and authorization evidence, then "
            "create only the corresponding local annotated Git tag."
        )
    )
    parser.add_argument(
        "--candidate-report",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--authorization-file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("."),
    )
    parser.add_argument("--remote", default="origin")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_dir = args.source_dir.resolve()

    try:
        candidate, candidate_raw = load_json(
            args.candidate_report.resolve()
        )
        authorization, _ = load_json(
            args.authorization_file.resolve()
        )
        candidate_digest = hashlib.sha256(
            candidate_raw
        ).hexdigest()

        require_candidate(candidate)
        require_authorization(
            authorization,
            candidate=candidate,
            candidate_digest=candidate_digest,
        )
        require_clean_tracked_tree(source_dir)
        require_source_alignment(source_dir, candidate)

        tag = str(candidate["release_tag"])
        require_tag_absent(source_dir, tag, args.remote)

        authorized_by = str(
            authorization["authorized_by"]
        ).strip()
        authorized_at = str(authorization["authorized_at"])
        message = "\n".join(
            [
                f"AGP Trust Primitive Engine {candidate['package_version']}",
                "",
                "Authorized local candidate tag materialization.",
                f"Candidate SHA-256: {candidate_digest}",
                f"Source commit: {candidate['source_commit']}",
                (
                    "Validation: "
                    f"{candidate['validation_total']}/"
                    f"{candidate['validation_total']} passed"
                ),
                f"Authorized by: {authorized_by}",
                f"Authorized at: {authorized_at}",
                "",
                "This operation does not push the tag, create a GitHub "
                "Release, or publish to PyPI.",
                "",
            ]
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
        ) as handle:
            handle.write(message)
            message_path = Path(handle.name)

        try:
            run_git(
                source_dir,
                "tag",
                "--annotate",
                tag,
                str(candidate["source_commit"]),
                "--file",
                str(message_path),
            )
        finally:
            message_path.unlink(missing_ok=True)

        object_type = run_git(
            source_dir,
            "cat-file",
            "-t",
            tag,
        ).stdout.strip()
        peeled = run_git(
            source_dir,
            "rev-list",
            "-n",
            "1",
            tag,
        ).stdout.strip()

        if object_type != "tag":
            raise RuntimeError(
                "materialized reference is not an annotated tag"
            )
        if peeled != candidate["source_commit"]:
            raise RuntimeError(
                "materialized tag does not peel to candidate commit"
            )
    except (
        KeyError,
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"LOCAL_ANNOTATED_TAG={tag}")
    print(f"TAGGED_COMMIT={peeled}")
    print(f"CANDIDATE_SHA256={candidate_digest}")
    print("TAG_PUSHED=no")
    print("GITHUB_RELEASE_CREATED=no")
    print("PYPI_PUBLISHED=no")
    print("AGP_AUTHORIZED_LOCAL_TAG_MATERIALIZATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

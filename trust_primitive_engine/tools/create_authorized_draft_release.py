#!/usr/bin/env python3
"""Create and verify one draft GitHub Release for an authorized tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Sequence


AUTH_STATEMENT = (
    "I authorize creation of the local annotated candidate tag."
)
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)


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


def run_git(
    source_dir: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run(
        ["git", *args],
        cwd=source_dir,
        check=check,
    )


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

    identity = authorization.get("authorized_by")
    if not isinstance(identity, str) or not identity.strip():
        raise RuntimeError("authorization identity is missing")

    instant = authorization.get("authorized_at")
    if (
        not isinstance(instant, str)
        or RFC3339_UTC.fullmatch(instant) is None
    ):
        raise RuntimeError(
            "authorization time must be RFC3339 UTC"
        )


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


def require_remote_tag(
    source_dir: Path,
    remote: str,
    candidate: dict[str, Any],
) -> None:
    tag = str(candidate["release_tag"])
    result = run_git(
        source_dir,
        "ls-remote",
        "--tags",
        remote,
        f"refs/tags/{tag}",
        f"refs/tags/{tag}^{{}}",
    )
    refs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        object_id, refname = line.split("\t", 1)
        refs[refname] = object_id

    peeled_ref = f"refs/tags/{tag}^{{}}"
    if peeled_ref not in refs:
        raise RuntimeError(
            f"remote annotated release tag is missing: {tag}"
        )
    if refs[peeled_ref] != candidate["source_commit"]:
        raise RuntimeError(
            "remote tag does not peel to candidate source commit"
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


def create_draft(
    source_dir: Path,
    repository: str,
    candidate: dict[str, Any],
    notes_file: Path,
) -> None:
    tag = str(candidate["release_tag"])
    version = str(candidate["package_version"])
    run(
        [
            "gh",
            "release",
            "create",
            tag,
            "--repo",
            repository,
            "--verify-tag",
            "--draft",
            "--title",
            f"AGP Trust Primitive Engine {version}",
            "--notes-file",
            str(notes_file),
        ],
        cwd=source_dir,
    )


def verify_draft(
    source_dir: Path,
    repository: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    tag = str(candidate["release_tag"])
    result = run(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            repository,
            "--json",
            (
                "tagName,name,isDraft,isPrerelease,"
                "publishedAt,assets"
            ),
        ],
        cwd=source_dir,
    )
    payload = json.loads(result.stdout)
    expected_name = (
        "AGP Trust Primitive Engine "
        f"{candidate['package_version']}"
    )
    expected = {
        "tagName": tag,
        "name": expected_name,
        "isDraft": True,
        "isPrerelease": False,
        "publishedAt": None,
        "assets": [],
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeError(
                f"draft release field mismatch: {key}"
            )
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a verified draft GitHub Release without publishing it."
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
        "--notes-file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--repository",
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
        require_remote_tag(
            source_dir,
            args.remote,
            candidate,
        )

        notes_file = args.notes_file.resolve()
        if not notes_file.is_file():
            raise RuntimeError(
                f"release notes file is missing: {notes_file}"
            )
        if not notes_file.read_text(
            encoding="utf-8"
        ).strip():
            raise RuntimeError("release notes file is empty")

        tag = str(candidate["release_tag"])
        require_release_absent(
            source_dir,
            args.repository,
            tag,
        )
        create_draft(
            source_dir,
            args.repository,
            candidate,
            notes_file,
        )
        verify_draft(
            source_dir,
            args.repository,
            candidate,
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

    print(f"DRAFT_RELEASE_TAG={tag}")
    print("DRAFT_RELEASE_CREATED=yes")
    print("RELEASE_PUBLISHED=no")
    print("GITHUB_RELEASE_ASSETS=0")
    print("PYPI_PUBLISHED=no")
    print("AGP_CONTROLLED_DRAFT_RELEASE_CREATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

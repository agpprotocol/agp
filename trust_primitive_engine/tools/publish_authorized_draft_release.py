#!/usr/bin/env python3
"""Publish one exactly authorized draft GitHub Release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any, Sequence


TAG_AUTH_STATEMENT = (
    "I authorize creation of the local annotated candidate tag."
)
PUBLICATION_AUTH_STATEMENT = (
    "I authorize publication of the verified draft GitHub Release, "
    "which will trigger the configured release workflow."
)
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
EXPECTED_WORKFLOW_NAME = "Publish AGP TPE to PyPI"


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


def canonical_sha256(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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


def require_tag_authorization(
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
        "statement": TAG_AUTH_STATEMENT,
    }
    for key, value in expected.items():
        if authorization.get(key) != value:
            raise RuntimeError(
                f"tag authorization field mismatch: {key}"
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


def read_release(
    source_dir: Path,
    repository: str,
    tag: str,
) -> dict[str, Any]:
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
                "tagName,name,isDraft,isPrerelease,createdAt,"
                "publishedAt,targetCommitish,assets,url"
            ),
        ],
        cwd=source_dir,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("Release response is not an object")
    return payload


def require_exact_draft(
    payload: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    expected_name = (
        "AGP Trust Primitive Engine "
        f"{candidate['package_version']}"
    )
    expected = {
        "tagName": candidate["release_tag"],
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

    created_at = payload.get("createdAt")
    if (
        not isinstance(created_at, str)
        or RFC3339_UTC.fullmatch(created_at) is None
    ):
        raise RuntimeError(
            "draft release creation time must be RFC3339 UTC"
        )

    url = payload.get("url")
    if not isinstance(url, str) or not url.strip():
        raise RuntimeError("draft release URL is missing")

    target = payload.get("targetCommitish")
    if target not in (
        candidate["source_commit"],
        candidate.get("source_branch"),
    ):
        raise RuntimeError(
            "draft release target does not match candidate source"
        )


def require_publication_authorization(
    authorization: dict[str, Any],
    *,
    candidate: dict[str, Any],
    candidate_digest: str,
    repository: str,
    draft_digest: str,
) -> None:
    expected = {
        "format": (
            "agp-tpe-release-publication-authorization-v1"
        ),
        "decision": "authorize-draft-release-publication",
        "candidate_sha256": candidate_digest,
        "draft_release_sha256": draft_digest,
        "repository": repository,
        "release_tag": candidate["release_tag"],
        "source_commit": candidate["source_commit"],
        "statement": PUBLICATION_AUTH_STATEMENT,
    }
    for key, value in expected.items():
        if authorization.get(key) != value:
            raise RuntimeError(
                f"publication authorization field mismatch: {key}"
            )

    identity = authorization.get("authorized_by")
    if not isinstance(identity, str) or not identity.strip():
        raise RuntimeError(
            "publication authorization identity is missing"
        )

    instant = authorization.get("authorized_at")
    if (
        not isinstance(instant, str)
        or RFC3339_UTC.fullmatch(instant) is None
    ):
        raise RuntimeError(
            "publication authorization time must be RFC3339 UTC"
        )


def publish_release(
    source_dir: Path,
    repository: str,
    tag: str,
) -> None:
    run(
        [
            "gh",
            "release",
            "edit",
            tag,
            "--repo",
            repository,
            "--draft=false",
        ],
        cwd=source_dir,
    )


def require_published_release(
    payload: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    expected_name = (
        "AGP Trust Primitive Engine "
        f"{candidate['package_version']}"
    )
    expected = {
        "tagName": candidate["release_tag"],
        "name": expected_name,
        "isDraft": False,
        "isPrerelease": False,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeError(
                f"published release field mismatch: {key}"
            )

    published_at = payload.get("publishedAt")
    if (
        not isinstance(published_at, str)
        or RFC3339_UTC.fullmatch(published_at) is None
    ):
        raise RuntimeError(
            "published release timestamp must be RFC3339 UTC"
        )

    target = payload.get("targetCommitish")
    if target not in (
        candidate["source_commit"],
        candidate.get("source_branch"),
    ):
        raise RuntimeError(
            "published release target does not match candidate"
        )


def find_release_workflow_run(
    source_dir: Path,
    repository: str,
    candidate: dict[str, Any],
    attempts: int,
    delay_seconds: float,
) -> dict[str, Any]:
    tag = str(candidate["release_tag"])
    for attempt in range(attempts):
        result = run(
            [
                "gh",
                "run",
                "list",
                "--repo",
                repository,
                "--event",
                "release",
                "--limit",
                "40",
                "--json",
                (
                    "databaseId,workflowName,event,status,"
                    "conclusion,headBranch,headSha,url"
                ),
            ],
            cwd=source_dir,
        )
        payload = json.loads(result.stdout)
        if not isinstance(payload, list):
            raise RuntimeError(
                "workflow run response is not a list"
            )
        for item in payload:
            if (
                isinstance(item, dict)
                and item.get("workflowName")
                == EXPECTED_WORKFLOW_NAME
                and item.get("event") == "release"
                and item.get("headBranch") == tag
                and item.get("headSha")
                == candidate["source_commit"]
            ):
                return item
        if attempt + 1 < attempts:
            time.sleep(delay_seconds)

    raise RuntimeError(
        "matching release workflow run was not observed"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish one exactly authorized draft Release and "
            "verify the matching release workflow run."
        )
    )
    parser.add_argument(
        "--candidate-report",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--tag-authorization-file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--publication-authorization-file",
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
    parser.add_argument(
        "--run-observation-attempts",
        type=int,
        default=12,
    )
    parser.add_argument(
        "--run-observation-delay-seconds",
        type=float,
        default=5.0,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_dir = args.source_dir.resolve()

    if args.run_observation_attempts < 1:
        print(
            "FAIL: run observation attempts must be positive",
            file=sys.stderr,
        )
        return 1
    if args.run_observation_delay_seconds < 0:
        print(
            "FAIL: run observation delay cannot be negative",
            file=sys.stderr,
        )
        return 1

    try:
        candidate, candidate_raw = load_json(
            args.candidate_report.resolve()
        )
        tag_authorization, _ = load_json(
            args.tag_authorization_file.resolve()
        )
        publication_authorization, _ = load_json(
            args.publication_authorization_file.resolve()
        )
        candidate_digest = hashlib.sha256(
            candidate_raw
        ).hexdigest()

        require_candidate(candidate)
        require_tag_authorization(
            tag_authorization,
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

        before = read_release(
            source_dir,
            args.repository,
            str(candidate["release_tag"]),
        )
        require_exact_draft(before, candidate)
        draft_digest = canonical_sha256(before)
        require_publication_authorization(
            publication_authorization,
            candidate=candidate,
            candidate_digest=candidate_digest,
            repository=args.repository,
            draft_digest=draft_digest,
        )

        publish_release(
            source_dir,
            args.repository,
            str(candidate["release_tag"]),
        )

        after = read_release(
            source_dir,
            args.repository,
            str(candidate["release_tag"]),
        )
        require_published_release(after, candidate)

        workflow_run = find_release_workflow_run(
            source_dir,
            args.repository,
            candidate,
            args.run_observation_attempts,
            args.run_observation_delay_seconds,
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

    print(
        f"PUBLISHED_RELEASE_TAG="
        f"{candidate['release_tag']}"
    )
    print(f"DRAFT_RELEASE_SHA256={draft_digest}")
    print("RELEASE_PUBLISHED=yes")
    print(
        f"RELEASE_WORKFLOW_RUN_ID="
        f"{workflow_run['databaseId']}"
    )
    print(
        f"RELEASE_WORKFLOW_RUN_STATUS="
        f"{workflow_run['status']}"
    )
    print("PYPI_PUBLICATION_TRIGGERED=yes")
    print("AGP_CONTROLLED_DRAFT_PUBLICATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

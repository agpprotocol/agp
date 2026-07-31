#!/usr/bin/env python3
"""Verify terminal success of one published AGP TPE release."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Sequence


EXPECTED_WORKFLOW_NAME = "Publish AGP TPE to PyPI"
EXPECTED_ASSET_PATTERNS = {
    "wheel": re.compile(r"^agp_tpe-[^-]+-py3-none-any[.]whl$"),
    "sdist": re.compile(r"^agp_tpe-[^-]+[.]tar[.]gz$"),
    "checksums": re.compile(r"^SHA256SUMS$"),
    "sbom": re.compile(r"^agp-tpe[.]cdx[.]json$"),
}
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]+)?Z$"
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


def require_release(
    payload: dict[str, Any],
    *,
    tag: str,
    version: str,
    source_commit: str,
) -> dict[str, str]:
    expected = {
        "tagName": tag,
        "name": f"AGP Trust Primitive Engine {version}",
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
    if target != source_commit:
        raise RuntimeError(
            "published release target does not match source commit"
        )

    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("published release assets are not a list")
    if len(assets) != 4:
        raise RuntimeError(
            "published release must contain exactly four assets"
        )

    matched: dict[str, str] = {}
    names: set[str] = set()
    for item in assets:
        if not isinstance(item, dict):
            raise RuntimeError("release asset is not an object")
        name = item.get("name")
        state = item.get("state")
        size = item.get("size")
        if not isinstance(name, str) or not name:
            raise RuntimeError("release asset name is missing")
        if name in names:
            raise RuntimeError("duplicate release asset name")
        names.add(name)
        if state != "uploaded":
            raise RuntimeError(
                f"release asset is not uploaded: {name}"
            )
        if not isinstance(size, int) or size <= 0:
            raise RuntimeError(
                f"release asset size is invalid: {name}"
            )

        classes = [
            kind
            for kind, pattern in EXPECTED_ASSET_PATTERNS.items()
            if pattern.fullmatch(name)
        ]
        if len(classes) != 1:
            raise RuntimeError(
                f"unexpected release asset: {name}"
            )
        kind = classes[0]
        if kind in matched:
            raise RuntimeError(
                f"duplicate release asset class: {kind}"
            )
        matched[kind] = name

    if set(matched) != set(EXPECTED_ASSET_PATTERNS):
        raise RuntimeError(
            "release asset classes are incomplete"
        )
    return matched


def read_workflow_run(
    source_dir: Path,
    repository: str,
    run_id: int,
) -> dict[str, Any]:
    result = run(
        [
            "gh",
            "run",
            "view",
            str(run_id),
            "--repo",
            repository,
            "--json",
            (
                "databaseId,workflowName,event,status,conclusion,"
                "headBranch,headSha,createdAt,updatedAt,url"
            ),
        ],
        cwd=source_dir,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("workflow run response is not an object")
    return payload


def require_workflow_run(
    payload: dict[str, Any],
    *,
    run_id: int,
    tag: str,
    source_commit: str,
) -> None:
    expected = {
        "databaseId": run_id,
        "workflowName": EXPECTED_WORKFLOW_NAME,
        "event": "release",
        "status": "completed",
        "conclusion": "success",
        "headBranch": tag,
        "headSha": source_commit,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise RuntimeError(
                f"release workflow field mismatch: {key}"
            )


def read_pypi(
    package_name: str,
    *,
    endpoint: str,
) -> dict[str, Any]:
    url = endpoint.format(package=package_name)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"PyPI lookup failed with HTTP {exc.code}: {url}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"PyPI lookup failed: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise RuntimeError("PyPI response is not an object")
    return payload


def require_pypi_release(
    payload: dict[str, Any],
    *,
    version: str,
) -> list[str]:
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        raise RuntimeError("PyPI releases map is missing")

    files = releases.get(version)
    if not isinstance(files, list) or len(files) != 2:
        raise RuntimeError(
            "PyPI release must contain exactly two distributions"
        )

    types: set[str] = set()
    names: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            raise RuntimeError(
                "PyPI distribution entry is not an object"
            )
        filename = item.get("filename")
        package_type = item.get("packagetype")
        size = item.get("size")
        yanked = item.get("yanked")
        upload_time = item.get("upload_time_iso_8601")
        digests = item.get("digests")

        if not isinstance(filename, str) or not filename:
            raise RuntimeError(
                "PyPI distribution filename is missing"
            )
        if package_type not in {"bdist_wheel", "sdist"}:
            raise RuntimeError(
                f"unexpected PyPI package type: {package_type}"
            )
        if package_type in types:
            raise RuntimeError(
                f"duplicate PyPI package type: {package_type}"
            )
        types.add(package_type)
        if not isinstance(size, int) or size <= 0:
            raise RuntimeError(
                f"invalid PyPI distribution size: {filename}"
            )
        if yanked is not False:
            raise RuntimeError(
                f"PyPI distribution is yanked: {filename}"
            )
        if (
            not isinstance(upload_time, str)
            or RFC3339_UTC.fullmatch(upload_time) is None
        ):
            raise RuntimeError(
                f"invalid PyPI upload timestamp: {filename}"
            )
        if (
            not isinstance(digests, dict)
            or not isinstance(digests.get("sha256"), str)
            or len(digests["sha256"]) != 64
        ):
            raise RuntimeError(
                f"missing PyPI SHA-256 digest: {filename}"
            )
        names.append(filename)

    if types != {"bdist_wheel", "sdist"}:
        raise RuntimeError(
            "PyPI release distribution classes are incomplete"
        )
    return sorted(names)


def read_verification_evidence(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(
            "release verification evidence is not an object"
        )
    return payload


def require_verification_evidence(
    payload: dict[str, Any],
    *,
    tag: str,
    repository: str,
) -> None:
    if payload.get("overall_status") != "passed":
        raise RuntimeError(
            "release attestation verification did not pass"
        )

    if payload.get("tag") != tag:
        raise RuntimeError(
            "verification evidence tag mismatch"
        )
    if payload.get("repository") != repository:
        raise RuntimeError(
            "verification evidence repository mismatch"
        )

    assets = payload.get("assets")
    if not isinstance(assets, list) or len(assets) != 4:
        raise RuntimeError(
            "verification evidence must cover four assets"
        )

    classes: set[str] = set()
    for item in assets:
        if not isinstance(item, dict):
            raise RuntimeError(
                "verification evidence asset is not an object"
            )
        asset_class = item.get("class")
        checksum = item.get("checksum")
        provenance = item.get("provenance")
        sbom = item.get("sbom")
        if asset_class not in EXPECTED_ASSET_PATTERNS:
            raise RuntimeError(
                f"unexpected verification asset class: {asset_class}"
            )
        if asset_class in classes:
            raise RuntimeError(
                f"duplicate verification asset class: {asset_class}"
            )
        classes.add(asset_class)
        if checksum != "passed":
            raise RuntimeError(
                f"checksum verification failed: {asset_class}"
            )
        if provenance != "passed":
            raise RuntimeError(
                f"provenance verification failed: {asset_class}"
            )
        expected_sbom = (
            "passed"
            if asset_class in {"wheel", "sdist"}
            else "not_applicable"
        )
        if sbom != expected_sbom:
            raise RuntimeError(
                f"SBOM verification mismatch: {asset_class}"
            )

    if classes != set(EXPECTED_ASSET_PATTERNS):
        raise RuntimeError(
            "verification evidence asset classes are incomplete"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify terminal success of one published AGP TPE "
            "GitHub and PyPI release."
        )
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument(
        "--verification-evidence",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path("."),
    )
    parser.add_argument(
        "--pypi-endpoint",
        default="https://pypi.org/pypi/{package}/json",
    )
    parser.add_argument(
        "--package-name",
        default="agp-tpe",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_dir = args.source_dir.resolve()

    if args.tag != f"tpe-v{args.version}":
        print(
            "FAIL: release tag does not match version",
            file=sys.stderr,
        )
        return 1

    try:
        release = read_release(
            source_dir,
            args.repository,
            args.tag,
        )
        assets = require_release(
            release,
            tag=args.tag,
            version=args.version,
            source_commit=args.source_commit,
        )

        workflow_run = read_workflow_run(
            source_dir,
            args.repository,
            args.workflow_run_id,
        )
        require_workflow_run(
            workflow_run,
            run_id=args.workflow_run_id,
            tag=args.tag,
            source_commit=args.source_commit,
        )

        pypi = read_pypi(
            args.package_name,
            endpoint=args.pypi_endpoint,
        )
        pypi_files = require_pypi_release(
            pypi,
            version=args.version,
        )

        evidence = read_verification_evidence(
            args.verification_evidence.resolve()
        )
        require_verification_evidence(
            evidence,
            tag=args.tag,
            repository=args.repository,
        )
    except (
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"TERMINAL_RELEASE_TAG={args.tag}")
    print(
        f"TERMINAL_RELEASE_WORKFLOW_RUN_ID="
        f"{args.workflow_run_id}"
    )
    print("TERMINAL_RELEASE_WORKFLOW_SUCCESS=yes")
    print("TERMINAL_RELEASE_ASSETS=4")
    print(
        "TERMINAL_RELEASE_ASSET_NAMES="
        + ",".join(assets[k] for k in sorted(assets))
    )
    print("PYPI_RELEASE_PRESENT=yes")
    print(
        "PYPI_RELEASE_FILES="
        + ",".join(pypi_files)
    )
    print("ATTESTATION_VERIFICATION_PASSED=yes")
    print("AGP_TERMINAL_RELEASE_PUBLICATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed readiness checks for an AGP TPE Python release."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Sequence


def run_git(source_dir: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source_dir), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.strip()


def load_project(source_dir: Path) -> tuple[str, str]:
    pyproject = source_dir / "pyproject.toml"
    payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = payload["project"]
    return str(project["name"]), str(project["version"])


def require_version_available(
    *,
    base_url: str,
    package_name: str,
    package_version: str,
    timeout: float,
) -> None:
    quoted_name = urllib.parse.quote(package_name, safe="")
    quoted_version = urllib.parse.quote(package_version, safe="")
    url = f"{base_url.rstrip('/')}/{quoted_name}/{quoted_version}/json"

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
        "refusing to republish existing version: "
        f"{package_name}=={published}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate package metadata, annotated tag identity, checkout "
            "identity, and PyPI version availability."
        )
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-dir", type=Path, default=Path("."))
    parser.add_argument("--expected-package", default="agp-tpe")
    parser.add_argument(
        "--pypi-base-url",
        default="https://pypi.org/pypi",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source_dir = args.source_dir.resolve()

    try:
        package_name, package_version = load_project(source_dir)
        expected_tag = f"tpe-v{package_version}"

        if package_name != args.expected_package:
            raise RuntimeError(
                f"unexpected package name: {package_name!r}"
            )

        if args.tag != expected_tag:
            raise RuntimeError(
                "release tag does not match pyproject.toml version: "
                f"{args.tag!r} != {expected_tag!r}"
            )

        tag_type = run_git(source_dir, "cat-file", "-t", args.tag)
        if tag_type != "tag":
            raise RuntimeError(
                f"release tag must be annotated: {args.tag!r}"
            )

        tag_commit = run_git(
            source_dir,
            "rev-list",
            "-n",
            "1",
            args.tag,
        )
        checkout_commit = run_git(source_dir, "rev-parse", "HEAD")

        if tag_commit != checkout_commit:
            raise RuntimeError(
                "checkout does not match release tag: "
                f"{checkout_commit} != {tag_commit}"
            )

        require_version_available(
            base_url=args.pypi_base_url,
            package_name=package_name,
            package_version=package_version,
            timeout=args.timeout,
        )
    except (
        KeyError,
        OSError,
        RuntimeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"PACKAGE_NAME={package_name}")
    print(f"PACKAGE_VERSION={package_version}")
    print(f"RELEASE_TAG={args.tag}")
    print(f"RELEASE_COMMIT={tag_commit}")
    print(
        "PYPI_VERSION_AVAILABLE: "
        f"{package_name}=={package_version}"
    )
    print("AGP_RELEASE_READINESS_PREFLIGHT_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

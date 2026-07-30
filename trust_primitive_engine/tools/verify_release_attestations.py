#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
EXPECTED_PATTERNS = {
    "wheel": "*.whl",
    "sdist": "*.tar.gz",
    "checksums": "SHA256SUMS",
    "sbom": "agp-tpe.cdx.json",
}


def run_command(args: list[str], cwd: Path | None = None) -> tuple[bool, str]:
    completed = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return completed.returncode == 0, completed.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_source_digest() -> str:
    ok, output = run_command(["git", "rev-parse", "HEAD"])
    if not ok or not output:
        raise RuntimeError("could not resolve checked-out source digest")
    return output.splitlines()[-1].strip()


def verify_checksum_manifest(
    release_dir: Path,
    manifest: Path,
) -> tuple[bool, dict[str, str], list[str]]:
    expected: dict[str, str] = {}
    errors: list[str] = []

    for raw_line in manifest.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            errors.append(f"invalid checksum line: {raw_line}")
            continue
        digest, name = parts
        normalized_name = name.lstrip("*")
        expected[normalized_name] = digest.lower()

    for name, digest in sorted(expected.items()):
        asset = release_dir / name
        if not asset.is_file():
            errors.append(f"checksum asset missing: {name}")
            continue
        actual = sha256_file(asset)
        if actual != digest:
            errors.append(
                f"checksum mismatch for {name}: expected {digest}, got {actual}"
            )

    return not errors, expected, errors


def write_reports(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "verification-report.json"
    summary_path = output_dir / "verification-summary.md"

    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Release attestation verification",
        "",
        f"- Repository: `{report['repository']}`",
        f"- Release tag: `{report['release_tag']}`",
        f"- Source ref: `{report['source_ref']}`",
        f"- Source digest: `{report['source_digest']}`",
        f"- Signer workflow: `{report['signer_workflow']}`",
        f"- Overall status: **{report['overall_status'].upper()}**",
        "",
        "| Asset | SHA-256 | Provenance | CycloneDX SBOM |",
        "|---|---|---|---|",
    ]

    for asset in report["assets"]:
        lines.append(
            "| `{name}` | `{sha256}` | {provenance} | {sbom} |".format(
                name=asset["name"],
                sha256=asset["sha256"],
                provenance=asset["provenance"],
                sbom=asset["sbom"],
            )
        )

    if report["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in report["errors"])

    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify published AGP release assets and attestations."
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    output_dir: Path = args.output_dir.resolve()
    release_dir = output_dir / "assets"

    if output_dir.exists():
        shutil.rmtree(output_dir)
    release_dir.mkdir(parents=True)

    source_digest = resolve_source_digest()
    source_ref = f"refs/tags/{args.tag}"
    errors: list[str] = []

    for pattern in EXPECTED_PATTERNS.values():
        ok, output = run_command(
            [
                "gh",
                "release",
                "download",
                args.tag,
                "--repo",
                args.repository,
                "--dir",
                str(release_dir),
                "--pattern",
                pattern,
                "--clobber",
            ]
        )
        if not ok:
            errors.append(
                f"release download failed for pattern {pattern}: {output}"
            )

    matched: dict[str, list[Path]] = {
        label: sorted(release_dir.glob(pattern))
        for label, pattern in EXPECTED_PATTERNS.items()
    }
    for label, paths in matched.items():
        if len(paths) != 1:
            errors.append(
                f"expected exactly one {label} asset, found {len(paths)}"
            )

    checksum_expected: dict[str, str] = {}
    if len(matched["checksums"]) == 1:
        checksum_ok, checksum_expected, checksum_errors = (
            verify_checksum_manifest(
                release_dir,
                matched["checksums"][0],
            )
        )
        if not checksum_ok:
            errors.extend(checksum_errors)

    assets: list[dict[str, str]] = []
    for asset in sorted(path for path in release_dir.iterdir() if path.is_file()):
        digest = sha256_file(asset)
        provenance_ok, provenance_output = run_command(
            [
                "gh",
                "attestation",
                "verify",
                str(asset),
                "--repo",
                args.repository,
                "--signer-workflow",
                args.signer_workflow,
                "--source-ref",
                source_ref,
                "--source-digest",
                source_digest,
                "--deny-self-hosted-runners",
            ]
        )
        if not provenance_ok:
            errors.append(
                f"provenance verification failed for {asset.name}: "
                f"{provenance_output}"
            )

        sbom_status = "not_applicable"
        if asset.suffix == ".whl" or asset.name.endswith(".tar.gz"):
            sbom_ok, sbom_output = run_command(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(asset),
                    "--repo",
                    args.repository,
                    "--signer-workflow",
                    args.signer_workflow,
                    "--source-ref",
                    source_ref,
                    "--source-digest",
                    source_digest,
                    "--predicate-type",
                    CYCLONEDX_PREDICATE,
                    "--deny-self-hosted-runners",
                ]
            )
            sbom_status = "passed" if sbom_ok else "failed"
            if not sbom_ok:
                errors.append(
                    f"SBOM verification failed for {asset.name}: {sbom_output}"
                )

        if asset.name in checksum_expected:
            expected_digest = checksum_expected[asset.name]
            if digest != expected_digest:
                errors.append(
                    f"manifest digest mismatch for {asset.name}"
                )

        assets.append(
            {
                "name": asset.name,
                "sha256": digest,
                "provenance": "passed" if provenance_ok else "failed",
                "sbom": sbom_status,
            }
        )

    report: dict[str, Any] = {
        "assets": assets,
        "errors": sorted(set(errors)),
        "overall_status": "passed" if not errors else "failed",
        "release_tag": args.tag,
        "repository": args.repository,
        "schema_version": "1",
        "signer_workflow": args.signer_workflow,
        "source_digest": source_digest,
        "source_ref": source_ref,
    }
    write_reports(report, output_dir)

    if errors:
        for error in report["errors"]:
            print(f"FAIL  {error}", file=sys.stderr)
        return 1

    print(
        "AGP release verification evidence: "
        f"{len(assets)} assets verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

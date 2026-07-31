#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / ".github/workflows/publish-pypi.yml"
RECOVERY = ROOT / ".github/workflows/verify-release-attestations.yml"
TOOL = ROOT / "trust_primitive_engine/tools/verify_release_attestations.py"
DOC = ROOT / "trust_primitive_engine/go/PHASE-6D-7F.md"
EXPECTED_TOTAL = 24


def main() -> int:
    publish = PUBLISH.read_text(encoding="utf-8")
    recovery = RECOVERY.read_text(encoding="utf-8")
    tool = TOOL.read_text(encoding="utf-8")
    document = DOC.read_text(encoding="utf-8")

    checks = [
        ("repository-owned verification tool exists", TOOL.is_file()),
        ("manual recovery workflow exists", RECOVERY.is_file()),
        ("Phase 6D-7F documentation exists", DOC.is_file()),
        ("tool accepts an explicit release tag", '--tag' in tool),
        ("tool accepts repository identity", '--repository' in tool),
        ("tool accepts signer workflow identity", '--signer-workflow' in tool),
        ("tool emits deterministic JSON evidence", 'verification-report.json' in tool),
        ("tool emits Markdown evidence", 'verification-summary.md' in tool),
        ("tool computes SHA-256 per asset", 'sha256_file' in tool),
        ("tool verifies checksum manifest", 'verify_checksum_manifest' in tool),
        ("tool verifies provenance", '"attestation",' in tool and '"verify",' in tool),
        ("tool verifies CycloneDX SBOM", 'https://cyclonedx.org/bom' in tool),
        ("tool rejects self-hosted provenance", '--deny-self-hosted-runners' in tool),
        ("tool enforces source tag ref", 'refs/tags/' in tool),
        ("tool enforces checked-out source digest", 'git", "rev-parse", "HEAD' in tool),
        (
            "publish workflow generates evidence through canonical gate",
            "Verify published release attestations" in publish
            and "verify_release_attestations.py" in publish
            and "--output-dir release-verification-report" in publish,
        ),
        (
            "publish workflow writes job summary",
            'GITHUB_STEP_SUMMARY' in publish,
        ),
        (
            "publish workflow uploads evidence",
            "Upload release verification evidence" in publish,
        ),
        (
            "evidence retention is explicit",
            "retention-days: 90" in publish
            and "retention-days: 90" in recovery,
        ),
        (
            "upload-artifact is immutable-pinned",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            in publish
            and "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            in recovery,
        ),
        (
            "recovery is workflow_dispatch only",
            "workflow_dispatch:" in recovery
            and "release:" not in recovery
            and "push:" not in recovery,
        ),
        (
            "recovery keeps trusted tooling separate from released source",
            "Check out trusted recovery tooling" in recovery
            and "git worktree add --detach released-source" in recovery
            and "working-directory: released-source" in recovery
            and "ref: ${{ inputs.tag }}" not in recovery,
        ),
        (
            "recovery has no publication action",
            "gh-action-pypi-publish" not in recovery
            and "gh release upload" not in recovery,
        ),
        (
            "documentation forbids destructive recovery",
            "Do not delete" in document
            and "do not rebuild" in document.lower()
            and "verification-only" in document,
        ),
    ]

    passed = 0
    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(
        "AGP release verification observability contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())

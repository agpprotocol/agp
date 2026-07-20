#!/usr/bin/env python3
"""
AGP 120-Second Demo

A dependency-free illustration of one AGP invariant:

Approvals must remain bound to the exact proposal that was reviewed.

This quick demo uses HMAC from Python's standard library so that it runs
without installing dependencies. The AGP conformance suites in the main
repository use Ed25519 and the complete protocol structures.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import time
from dataclasses import dataclass
from typing import Any


# ANSI output is disabled automatically when stdout is not interactive.
USE_COLOR = sys.stdout.isatty()


def color(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return color(text, "32")


def red(text: str) -> str:
    return color(text, "31")


def yellow(text: str) -> str:
    return color(text, "33")


def bold(text: str) -> str:
    return color(text, "1")


def pause(seconds: float, enabled: bool) -> None:
    if enabled:
        time.sleep(seconds)


def canonical_json(value: Any) -> bytes:
    """
    Produce deterministic JSON bytes for this illustrative demo.

    The normative AGP specification must define canonicalization precisely.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class Authority:
    name: str
    role: str
    secret: bytes

    def approve(self, proposal_root: str) -> str:
        message = f"AGP-DEMO-APPROVE:{proposal_root}".encode("utf-8")
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()

    def verify(self, proposal_root: str, approval: str) -> bool:
        expected = self.approve(proposal_root)
        return hmac.compare_digest(expected, approval)


def divider() -> None:
    print("-" * 62)


def short_digest(digest: str) -> str:
    return f"{digest[:12]}…{digest[-8:]}"


def run_demo(happy_path: bool, fast: bool) -> int:
    pauses = not fast

    security = Authority(
        name="Security Agent",
        role="security-approver",
        secret=b"demo-security-secret",
    )
    operations = Authority(
        name="Operations Agent",
        role="operations-approver",
        secret=b"demo-operations-secret",
    )

    authorities = [security, operations]

    original_proposal = {
        "proposal_id": "deploy-payment-service-2026-07-20",
        "action": "deploy",
        "service": "payment-service",
        "artifact": "payment-service:2.4.1",
        "environment": "production",
        "requested_by": "release-agent",
    }

    original_root = sha256_hex(original_proposal)

    approvals = {
        authority.name: authority.approve(original_root)
        for authority in authorities
    }

    print()
    print(bold("=" * 62))
    print(bold(" AGP DEMO — 120-SECOND CHALLENGE"))
    print(bold("=" * 62))
    print()
    print("Scenario: deploy payment-service:2.4.1 to production")
    print()

    pause(0.5, pauses)

    print(green("✓ Proposal created"))
    print(f"  Input root: {short_digest(original_root)}")

    pause(0.5, pauses)

    for authority in authorities:
        print(green(f"✓ {authority.name} approved the proposal"))

    pause(0.7, pauses)

    divider()

    coordinator_state = dict(original_proposal)

    if happy_path:
        print()
        print("Coordinator preserves the approved proposal.")
    else:
        print()
        print(yellow("Coordinator modifies the artifact after approval…"))
        coordinator_state["artifact"] = "payment-service:2.4.2-unreviewed"

    final_root = sha256_hex(coordinator_state)

    print()
    print(f"Approved root: {short_digest(original_root)}")
    print(f"Final root:    {short_digest(final_root)}")

    pause(0.8, pauses)

    divider()
    print()
    print(bold("WORKFLOW BASELINE"))
    print()

    # A coordinator-trusting workflow sees two stored approvals and trusts the
    # coordinator's final action state. It does not re-bind those approvals to
    # the exact payload being executed.
    workflow_approved = len(approvals) >= 2

    if workflow_approved:
        print(green("✓ Deployment approved"))
        print("  Reason: required approval count is present.")
    else:
        print(red("✗ Deployment rejected"))

    pause(0.9, pauses)

    divider()
    print()
    print(bold("AGP VERIFICATION"))
    print()

    approvals_valid_for_original = all(
        authority.verify(original_root, approvals[authority.name])
        for authority in authorities
    )

    roots_match = hmac.compare_digest(original_root, final_root)

    if approvals_valid_for_original:
        print(green("✓ Approval records are valid"))
    else:
        print(red("✗ Invalid approval record"))
        return 2

    if roots_match:
        print(green("✓ Final proposal matches the approved input root"))
        agp_result = "APPROVED"
    else:
        print(red("✗ INPUT_ROOT_MISMATCH"))
        print("  The executed payload differs from the reviewed proposal.")
        agp_result = "REJECTED"

    pause(0.9, pauses)

    divider()
    print()
    print(bold("INDEPENDENT AUDIT"))
    print()

    audit_original_root = sha256_hex(original_proposal)
    audit_final_root = sha256_hex(coordinator_state)

    audit_reproduced = (
        audit_original_root == original_root
        and audit_final_root == final_root
        and all(
            authority.verify(
                audit_original_root,
                approvals[authority.name],
            )
            for authority in authorities
        )
    )

    if audit_reproduced:
        print(green("✓ Decision reproduced independently"))
        print(green("✓ Approval integrity verified"))
    else:
        print(red("✗ Audit could not reproduce the decision"))
        return 3

    print()
    divider()

    if happy_path:
        print(green("DEMO RESULT: VALID GOVERNANCE DECISION"))
        print("The final payload is exactly the payload that was approved.")
    else:
        print(red("DEMO RESULT: TAMPERING DETECTED"))
        print("The workflow accepted the coordinator state.")
        print("AGP rejected it because approvals were bound to another input.")

    print()
    print(f"AGP resolution: {agp_result}")
    print()
    print(
        "Note: this is a dependency-free explanatory demo. "
        "See the repository's signed conformance suites for the "
        "Ed25519-based protocol experiments."
    )
    print()

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the AGP 120-Second Challenge."
    )
    parser.add_argument(
        "--happy-path",
        action="store_true",
        help="Run a valid deployment instead of the tampering scenario.",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Disable pauses between demo stages.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_demo(
        happy_path=args.happy_path,
        fast=args.fast,
    )


if __name__ == "__main__":
    raise SystemExit(main())

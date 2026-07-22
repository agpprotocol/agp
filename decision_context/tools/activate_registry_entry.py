#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "registry.json"

OBJECT_ID = "agp.decision-context/1"
EXPECTED_RESERVED_SCHEMA = "registry/schemas/reserved.schema.json"
ACTIVE_SCHEMA = "registry/schemas/agp.decision-context-1.schema.json"
ACTIVE_DESCRIPTION = (
    "Immutable, canonical input context for an AGP decision, "
    "excluding decisions, outcomes, execution state, and transparency position."
)


def main() -> None:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    objects = registry.get("objects")
    if not isinstance(objects, list):
        raise SystemExit("registry/registry.json: 'objects' must be an array")

    matches = [entry for entry in objects if entry.get("id") == OBJECT_ID]
    if len(matches) != 1:
        raise SystemExit(
            f"Expected exactly one {OBJECT_ID!r} entry, found {len(matches)}"
        )

    entry = matches[0]
    current_status = entry.get("status")
    current_schema = entry.get("schema")

    if current_status not in {"reserved", "active"}:
        raise SystemExit(
            f"Refusing to modify unexpected status: {current_status!r}"
        )

    if current_schema not in {EXPECTED_RESERVED_SCHEMA, ACTIVE_SCHEMA}:
        raise SystemExit(
            f"Refusing to modify unexpected schema: {current_schema!r}"
        )

    entry["status"] = "active"
    entry["description"] = ACTIVE_DESCRIPTION
    entry["schema"] = ACTIVE_SCHEMA

    REGISTRY_PATH.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Activated {OBJECT_ID}")
    print(f"Schema: {ACTIVE_SCHEMA}")


if __name__ == "__main__":
    main()

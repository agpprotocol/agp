#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import zipfile
from collections import deque
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

SPEC_VERSION = "1.7"
SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{canonicalize_name(name)}@{version}"


def active_requirement(raw: str) -> Requirement | None:
    requirement = Requirement(raw)
    if requirement.marker is None:
        return requirement
    environment = default_environment()
    environment["extra"] = ""
    return requirement if requirement.marker.evaluate(environment) else None


def read_wheel_metadata(path: Path) -> tuple[str, str, list[str], str | None]:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("expected exactly one wheel METADATA file")
        text = archive.read(names[0]).decode("utf-8")

    package_name = None
    version = None
    license_name = None
    requirements: list[str] = []

    for line in text.splitlines():
        if line.startswith("Name: "):
            package_name = line[6:].strip()
        elif line.startswith("Version: "):
            version = line[9:].strip()
        elif line.startswith("License: "):
            license_name = line[9:].strip()
        elif line.startswith("Requires-Dist: "):
            requirements.append(line[15:].strip())

    if not package_name or not version:
        raise ValueError("wheel metadata lacks name or version")

    return package_name, version, requirements, license_name


def collect_graph(
    root_requirements: list[str],
) -> tuple[list[dict[str, object]], dict[str, list[str]], list[str]]:
    queue: deque[str] = deque()
    direct_refs: list[str] = []

    for raw in root_requirements:
        requirement = active_requirement(raw)
        if requirement is None:
            continue
        distribution = importlib.metadata.distribution(requirement.name)
        actual_name = distribution.metadata["Name"] or requirement.name
        direct_refs.append(purl(actual_name, distribution.version))
        queue.append(requirement.name)

    seen: set[str] = set()
    components: dict[str, dict[str, object]] = {}
    graph: dict[str, list[str]] = {}

    while queue:
        requested_name = queue.popleft()
        normalized = canonicalize_name(requested_name)
        if normalized in seen:
            continue
        seen.add(normalized)

        distribution = importlib.metadata.distribution(requested_name)
        actual_name = distribution.metadata["Name"] or requested_name
        version = distribution.version
        reference = purl(actual_name, version)

        components[reference] = {
            "type": "library",
            "bom-ref": reference,
            "name": canonicalize_name(actual_name),
            "version": version,
            "purl": reference,
        }

        children: list[str] = []
        for raw in distribution.requires or []:
            requirement = active_requirement(raw)
            if requirement is None:
                continue
            child = importlib.metadata.distribution(requirement.name)
            child_name = child.metadata["Name"] or requirement.name
            child_ref = purl(child_name, child.version)
            children.append(child_ref)
            queue.append(requirement.name)

        graph[reference] = sorted(set(children))

    return (
        [components[key] for key in sorted(components)],
        {key: graph[key] for key in sorted(graph)},
        sorted(set(direct_refs)),
    )


def build_bom(wheel: Path, sdist: Path) -> dict[str, object]:
    name, version, requirements, license_name = read_wheel_metadata(wheel)
    root_ref = purl(name, version)
    components, graph, direct_refs = collect_graph(requirements)

    root_component: dict[str, object] = {
        "type": "library",
        "bom-ref": root_ref,
        "name": canonicalize_name(name),
        "version": version,
        "purl": root_ref,
        "externalReferences": [
            {
                "type": "distribution",
                "url": wheel.name,
                "hashes": [{"alg": "SHA-256", "content": sha256(wheel)}],
            },
            {
                "type": "distribution",
                "url": sdist.name,
                "hashes": [{"alg": "SHA-256", "content": sha256(sdist)}],
            },
        ],
    }
    if license_name:
        root_component["licenses"] = [{"license": {"name": license_name}}]

    dependencies = [{"ref": root_ref, "dependsOn": direct_refs}]
    dependencies.extend(
        {"ref": reference, "dependsOn": children}
        for reference, children in graph.items()
    )

    return {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "agp-release-sbom-generator",
                        "version": "1",
                    }
                ]
            },
            "component": root_component,
        },
        "components": components,
        "dependencies": dependencies,
        "compositions": [
            {
                "aggregate": "complete",
                "assemblies": [root_ref],
            }
        ],
    }


def validate_bom(bom: dict[str, object]) -> None:
    if bom.get("bomFormat") != "CycloneDX":
        raise ValueError("invalid bomFormat")
    if bom.get("specVersion") != SPEC_VERSION:
        raise ValueError("invalid specVersion")

    metadata = bom.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("missing metadata")
    root = metadata.get("component")
    if not isinstance(root, dict) or not root.get("bom-ref"):
        raise ValueError("missing root component")

    components = bom.get("components")
    dependencies = bom.get("dependencies")
    if not isinstance(components, list) or not components:
        raise ValueError("missing runtime components")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("missing dependency graph")

    refs = {root["bom-ref"]}
    refs.update(item["bom-ref"] for item in components)

    for item in dependencies:
        if item["ref"] not in refs:
            raise ValueError("unknown dependency ref")
        for child in item.get("dependsOn", []):
            if child not in refs:
                raise ValueError("unknown dependency target")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    bom = build_bom(args.wheel, args.sdist)
    validate_bom(bom)

    encoded = json.dumps(
        bom,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")

    print(f"sbom_component={bom['metadata']['component']['purl']}")
    print(f"sbom_runtime_components={len(bom['components'])}")
    print(f"sbom_dependencies={len(bom['dependencies'])}")
    print(f"sbom_sha256={hashlib.sha256(encoded.encode('utf-8')).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

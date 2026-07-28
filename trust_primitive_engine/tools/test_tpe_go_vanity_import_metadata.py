#!/usr/bin/env python3
"""Validate public Go vanity-import metadata deployed by GitHub Pages."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

EXPECTED = {
    ROOT / "site/agp/trust-primitive-engine/index.html": {
        "go-import": (
            "agpprotocol.org/agp/trust-primitive-engine "
            "git https://github.com/agpprotocol/agp "
            "trust_primitive_engine/go"
        ),
        "go-source": (
            "agpprotocol.org/agp/trust-primitive-engine "
            "https://github.com/agpprotocol/agp "
            "https://github.com/agpprotocol/agp/tree/main/"
            "trust_primitive_engine/go "
            "https://github.com/agpprotocol/agp/blob/main/"
            "trust_primitive_engine/go/{dir}/{file}#L{line}"
        ),
    },
    ROOT / "site/agp/signed-decision-context/index.html": {
        "go-import": (
            "agpprotocol.org/agp/signed-decision-context "
            "git https://github.com/agpprotocol/agp "
            "signed_decision_context/go"
        ),
        "go-source": (
            "agpprotocol.org/agp/signed-decision-context "
            "https://github.com/agpprotocol/agp "
            "https://github.com/agpprotocol/agp/tree/main/"
            "signed_decision_context/go "
            "https://github.com/agpprotocol/agp/blob/main/"
            "signed_decision_context/go/{dir}/{file}#L{line}"
        ),
    },
}


class MetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.metadata: dict[str, list[str | None]] = {}

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag != "meta":
            return

        values = dict(attrs)
        name = values.get("name")
        if name not in {"go-import", "go-source"}:
            return

        self.metadata.setdefault(name, []).append(
            values.get("content")
        )


def main() -> int:
    passed = 0

    for path, expected in EXPECTED.items():
        if not path.is_file():
            raise AssertionError(f"missing vanity page: {path}")

        parser = MetadataParser()
        parser.feed(path.read_text(encoding="utf-8"))

        for metadata_name in ("go-import", "go-source"):
            actual = parser.metadata.get(metadata_name, [])
            wanted = [expected[metadata_name]]

            if actual != wanted:
                raise AssertionError(
                    f"{path}: {metadata_name}={actual!r}; "
                    f"expected={wanted!r}"
                )

            print(
                f"PASS  {path.relative_to(ROOT)} "
                f"{metadata_name}"
            )
            passed += 1

    if passed != 4:
        raise AssertionError(
            f"expected 4 checks, observed {passed}"
        )

    print(
        "TPE Go vanity import metadata: "
        f"{passed}/{passed} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

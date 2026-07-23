"""Deterministic primitive registration and resolution."""

from __future__ import annotations

from collections.abc import Iterable

from .primitive import Primitive


class PrimitiveRegistry:
    """Registry mapping primitive type identifiers to implementations."""

    def __init__(
        self,
        primitives: Iterable[Primitive] = (),
    ) -> None:
        self._primitives: dict[str, Primitive] = {}

        for primitive in primitives:
            self.register(primitive)

    def register(self, primitive: Primitive) -> None:
        primitive_type = primitive.TYPE

        if not isinstance(primitive_type, str) or not primitive_type:
            raise ValueError(
                "primitive TYPE must be a non-empty string"
            )

        if primitive_type in self._primitives:
            raise ValueError(
                f"primitive already registered: {primitive_type}"
            )

        self._primitives[primitive_type] = primitive

    def resolve(self, primitive_type: str) -> Primitive:
        try:
            return self._primitives[primitive_type]
        except KeyError as exc:
            raise KeyError(
                f"primitive not registered: {primitive_type}"
            ) from exc

    def contains(self, primitive_type: str) -> bool:
        return primitive_type in self._primitives

    def types(self) -> tuple[str, ...]:
        return tuple(sorted(self._primitives))

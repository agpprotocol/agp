# Go TPE Phase 6A-1 — Leaf Primitive Parity Inventory

This phase freezes the complete cross-language leaf primitive inventory.

The canonical manifest lists all 27 Trust Policy leaf primitives implemented
by the Python and Go TPE runtimes. Every primitive declares one future
satisfied vector and one future unsatisfied vector.

The inventory test independently discovers Python `TYPE` declarations and Go
primitive and validation constants. It fails when either implementation adds,
removes, or renames a primitive without updating the shared parity manifest.

This phase does not yet claim evaluation-result parity. Phase 6A-2 will add
the 54 executable vectors and byte-identical comparison.

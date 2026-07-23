# TPE engine core

This package introduces the internal contracts used by Trust Primitive Engine
plugins:

- `Primitive`
- `PrimitiveRegistry`
- `EvaluationState`
- `PrimitiveResult`

Commit 1 intentionally does not connect these classes to the existing TPE 2.0
evaluator. The public behavior and the 18-case conformance suite must remain
unchanged.

The next commits migrate the existing primitives to this interface one at a
time.

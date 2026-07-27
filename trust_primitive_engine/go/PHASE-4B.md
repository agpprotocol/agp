# Go TPE Phase 4B Public Evaluation API

## Scope

This increment freezes the first reusable public evaluation facade:

```go
func Evaluate(
    input EvaluationInput,
    root Policy,
    policySet []Policy,
) (Evaluation, error)
```

The public package owns its input and output types. Callers do not import or
depend on `internal/model` or `internal/engine`.

Policy unsatisfaction is represented by `Evaluation.Status`; the error return
is reserved for fatal validation, reference, and execution failures.

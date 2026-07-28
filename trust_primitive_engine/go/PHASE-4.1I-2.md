# Go TPE Phase 4.1I-2 Deterministic Temporal Evaluation

This increment implements the `time_window` primitive in the Go TPE.

Both bounds are required non-negative safe JSON integers and the interval is
inclusive. Evaluation uses only the authenticated Decision Context
`evaluation_time`; an absent value fails closed with position `missing`.
No local clock or inferred timestamp is consulted.

Observed positions are `missing`, `before`, `inside`, and `after`.
Unsatisfied results emit `TIME_WINDOW_NOT_SATISFIED`.

The top-level evaluation shape remains unchanged. `evaluation_time` is
projected only into the temporal primitive's `observed` object and is not
added to the stable Trust Policy Evaluation 2 result.

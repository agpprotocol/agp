# Go TPE Phase 4.1I-1 Evaluation Time Projection

This increment projects the authenticated Decision Context
`evaluation_time` into the public and internal Go TPE context models.

The field is represented as `*int64` so the implementation preserves the
semantic distinction between an absent value and Unix epoch zero. Public
to internal conversion detaches the pointer.

The existing Signed Decision Context path already decodes the verified
context through `parser.Decode`, so integer JSON tokens remain exact.

This phase intentionally adds no temporal primitive dispatch and does not
change the public evaluation output shape.

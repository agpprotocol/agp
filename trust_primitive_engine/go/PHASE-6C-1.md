# Phase 6C-1 — External Go integration guide

Phase 6C-1 documents the complete public consumer boundary for
`tpe.EvaluateSigned`.

It adds:

- a satisfied external integration example;
- a rejected tampered-signature example;
- typed error handling through `tpe.ErrorCode`;
- explicit separation between signing infrastructure and Go evaluation;
- guidance for handling policy outcomes versus verification failures.

The examples import only the public TPE package and contain no private key
material.

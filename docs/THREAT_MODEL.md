# Threat Model

## Assets

- governance inputs;
- authority membership and roles;
- evidence manifests;
- ballots, objections and vetoes;
- decision receipts;
- audit history.

## Adversaries

AGP considers a malicious or compromised coordinator, compromised authority
keys, revoked authorities continuing to vote, replay attacks, storage
manipulation and participant equivocation.

## Detectable attacks in the current prototype

- payload and signature tampering;
- unknown, expired, revoked or not-yet-valid keys;
- envelope replay;
- stale evidence;
- duplicate ballots;
- replaced input roots;
- omitted, reordered, modified or truncated log events;
- forked histories.

## Out of scope

- endpoint compromise before signing;
- false but correctly signed evidence;
- coercion or collusion among sufficient authorities;
- confidentiality of governance content;
- global distributed consensus;
- availability under denial-of-service;
- legal enforceability.

This is experimental research software and has not received an independent
security audit.

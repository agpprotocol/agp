# Agent Governance Protocol (AGP)

AGP is an experimental governance layer for decisions made by multiple agents.

- MCP connects agents to tools and data.
- A2A connects agents to other agents.
- AGP governs how a group reaches a verifiable decision.

## Current evidence

- Semantic conformance: 260/260 vectors
- Signed envelope conformance: 10/10 vectors
- Transparency-log conformance: 8/8 vectors
- Independent Python and Go implementations
- Byte-identical receipts

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-v0.4.txt
python3 run_all_v0.5.py
```

## Core claim

AGP does not merely route approvals. It defines authority, evidence binding,
objections, vetoes, deterministic resolution, signatures and a tamper-evident
decision history.

## Status

Experimental. The remaining question is product necessity: whether the added
guarantees justify the integration cost compared with conventional workflows.

# AuditLens

An AI-assisted smart-contract security workbench built on top of Slither. Slither remains the
deterministic static-analysis engine; AuditLens adds a web UI and three layers of interpretation
around it, kept strictly separate:

```
Solidity/Vyper → Slither (static) → AI triage (hypotheses) → attack-path graph → dynamic verification → report
```

AuditLens never presents AI output as fact. A finding is only "verified" when a controlled
exploit test reproduced it in a sandbox.

## Running

```bash
pip install -e ".[workbench]"      # fastapi, uvicorn, networkx, python-multipart
auditlens                          # serves http://127.0.0.1:8800
```

Open the URL and click **Run demo scan**, or upload `.sol` / `.vy` files. No CLI knowledge needed.

## Architecture

| Module | Responsibility |
|--------|----------------|
| `scanner/` | Runs Slither via its Python API, extracts structured `FunctionEvidence`, orchestrates stages |
| `ai/` | Provider abstraction (`anthropic`/`openai`/`local`), structured-JSON triage, heuristic fallback |
| `graph/` | NetworkX security graph; access-control and per-finding attack paths |
| `verification/` | Controlled Foundry exploit templates + sandboxed runner |
| `reports/` | Dashboard summary and Markdown/JSON reports |
| `api/` | FastAPI app + in-memory scan store |
| `frontend/` | Zero-build SPA (HTML/CSS/JS) served by the API |

## AI provider

Triage uses the heuristic fallback unless a provider is configured via environment:

```bash
export WORKBENCH_AI_PROVIDER=anthropic      # or openai, local
export ANTHROPIC_API_KEY=...                # or OPENAI_API_KEY
export WORKBENCH_AI_MODEL=claude-sonnet-5   # optional
```

The AI layer only turns a prompt into text. It never executes commands, and every response is
validated against a schema; invalid output degrades to the heuristic assessment.

## Dynamic verification

Verification is opt-in and safe by design:

- The model supplies only structured **parameters**; test code comes from fixed templates.
- `forge test` is invoked with a fixed argv (never a shell string), under bubblewrap with
  no network, and with wall-clock and output limits.
- Without Foundry installed AuditLens reports **INCONCLUSIVE** and shows the generated test —
  it never fabricates a pass/fail.

### Enabling live verification

```bash
# 1. Install Foundry (forge + anvil)
curl -L https://foundry.paradigm.xyz | bash && ~/.foundry/bin/foundryup

# 2. Vendor forge-std for offline compilation inside the sandbox
git clone --depth 1 https://github.com/foundry-rs/forge-std /tmp/forge-std
cp -r /tmp/forge-std/src slither/tools/workbench/verification/vendor/forge-std/

# 3. Pre-download the solc Foundry needs (the sandbox has no network)
cd /tmp/forge-std && forge build
```

AuditLens auto-detects `~/.foundry/bin`, so no PATH changes are needed. On startup
`GET /api/status` reports `"foundry": true` and the Verification page shows a green
"sandbox ready" banner. The bundled `VulnerableBank.withdraw()` reentrancy then reports
**VERIFIED** with on-chain evidence (contract drained from 5 ETH to 0).

The sandbox binds only `/usr`, the Foundry bin dir, the solc cache and the throwaway
project dir; `--unshare-net` removes network access entirely.

## Supported vulnerability classes

Reentrancy, access control, and unchecked external calls. New classes are added by extending
`CATEGORY_BY_DETECTOR` (evidence), a path builder in `graph/`, and optionally a template in
`verification/templates.py`.

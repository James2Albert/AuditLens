# AuditLens

**AI-assisted smart-contract security workbench, built on top of [Slither](https://github.com/crytic/slither).**

AuditLens turns Slither from a command-line static analyzer into a web-based security
workbench that walks you through a full investigation:

```
Detect  →  Understand  →  Trace  →  Verify  →  Fix  →  Prove
(Slither)   (AI triage)  (graph)  (Foundry)  (patch)  (ledger + report)
```

Slither remains the deterministic analysis engine underneath. AuditLens adds three layers of
interpretation around it, and — critically — keeps them visually and conceptually separate:

| Layer | Source of truth | Trust level |
|-------|-----------------|-------------|
| **Static finding** | Slither detectors | Deterministic fact |
| **AI assessment** | LLM (or heuristic) reasoning over Slither's evidence | Hypothesis |
| **Execution evidence** | A controlled exploit test executed in a sandbox | Observed result of that run |
| **Remediation evidence** | A candidate patch re-tested against the same exploit + a regression test | Observed result of those runs |

A finding is only ever called "verified" when a real exploit test reproduced it inside an
isolated Foundry sandbox. AI output is always labelled a hypothesis.

---

## Table of contents

1. [What was built](#what-was-built)
2. [Architecture](#architecture)
3. [Install on a new machine](#install-on-a-new-machine)
4. [Running AuditLens](#running-auditlens)
5. [Using the workbench](#using-the-workbench)
6. [AI provider configuration](#ai-provider-configuration)
7. [Dynamic verification & the sandbox](#dynamic-verification--the-sandbox)
8. [Security model](#security-model)
9. [Testing](#testing)
10. [Extending AuditLens](#extending-auditlens)
11. [Troubleshooting](#troubleshooting)
12. [API reference](#api-reference)
13. [Evidence ledger](#evidence-ledger)
14. [Patch & regression validation](#patch--regression-validation)
15. [Benchmark](#benchmark)
16. [Limitations](#limitations)
17. [Finals demo script](#finals-demo-script)

---

## What was built

AuditLens is a self-contained tool living at `slither/tools/workbench/` inside the Slither
codebase. **No Slither internals were modified** — it consumes Slither purely through its
public Python API. The only change to the base project is two lines in `pyproject.toml`
(a console-script entry point and an optional-dependency group).

Feature summary:

- **Contract upload / demo** — drag-and-drop `.sol`/`.vy` files, or run the bundled
  deliberately-vulnerable `VulnerableBank.sol`. No CLI knowledge required.
- **Static analysis** — runs all Slither detectors and extracts structured *evidence* for each
  finding (the function's state reads/writes, external calls, modifiers, whether it is
  protected, whether it sends ETH, its callers, source location, and code).
- **AI triage** — sends that evidence (not the raw contract) to an LLM through a provider
  abstraction, which returns a structured, schema-validated assessment: classification,
  confidence, preconditions, evidence, impact, remediation, candidate attack steps. Falls back
  to a transparent rule-based heuristic when no API key is configured.
- **Attack-path analysis** — builds a security graph with NetworkX and derives candidate
  attack paths (reentrancy, privilege-escalation via access control, unchecked calls),
  rendered as an interactive graph and a step-by-step view.
- **Dynamic verification** — fills a controlled Foundry test template with structured
  parameters and executes it in a bubblewrap sandbox with no network. Reports
  `VERIFIED` / `NOT_VERIFIED` / `INCONCLUSIVE` / `VERIFICATION_ERROR` — never a fake result.
- **Exploit-to-impact verification** — forge's JSON output is parsed per test; each run records
  a run ID, the test's SHA-256, a digest of the sources, the forge version, the exit code and
  whether it ran sandboxed. Impact is computed only from values the test logged (balances
  before/after, a solvency invariant, re-entry counts) and is labelled as a local-fixture
  observation.
- **Security Evidence Ledger** — SQLite-backed, hash-chained records that keep static facts, AI
  hypotheses, execution evidence and remediation evidence apart. Scans persist across restarts.
- **OWASP Smart Contract Top 10 coverage with execution evidence** — SC05 reentrancy
  (`reentrancy-eth`) and SC01 access control (privilege escalation derived by an AuditLens graph
  rule over Slither's analysis, plus Slither's `suicidal` / `arbitrary-send-eth` family).
- **Patch & regression validation** — deterministic patches (checks-effects-interactions for
  reentrancy-eth, an access check for privilege escalation), or a patch the user supplies; validated against the original exploit test, a
  legitimate-use test and a Slither re-run, without touching the user's files.
- **Proof-carrying audit** — a downloadable bundle (sources, exact tests, ledger, report)
  that anyone can re-execute with `auditlens verify-bundle`: hashes, the ledger chain and every
  recorded test outcome are checked; any edit is reported as *tampered*.
- **Exploit regression memory** — every proven exploit becomes a regression test;
  `auditlens recheck bundle.zip src/` runs them against new code and exits 1 on a regression.
- **Drain timeline** — the target's balance recorded at every attacker callback, drawn for the
  original and the patched run on one chart.
- **AI hypothesis scorecard** — AI/heuristic predictions graded against execution (confirmed,
  refuted, missed, correctly dismissed, untested).
- **Reports** — Markdown / JSON export with evidence classification, run provenance, measured
  impact, patch validation and ledger hashes.
- **Explainable security score** — `100 − Σ deductions`, one deduction per root cause
  (vulnerability class × function) weighted by its worst finding: High 20 / Medium 8 / Low 3,
  or 30 / 15 / 6 when an exploit was verified (verification raises the weight once instead of
  counting twice). The Overview and the report list every deduction. Demo: **29**; with both
  generated patches applied and rescanned: 89 (unchecked call + zero-check remain);
  `demo/benchmark/fixed.sol`: 100. Validating a patch does not change the score — scanning the
  fixed code does.
- **Dashboard** — security score, severity breakdown, AI-flagged counts, verified-exploit
  count, attack-path count.

---

## Architecture

```
Browser (SPA)
     │  HTTP / JSON
     ▼
FastAPI app  (api/app.py)
     │
     ▼
ScanStore  (api/store.py)         ── in-memory, runs each scan in a background thread
     │
     ▼
Orchestrator  (scanner/orchestrator.py)   ── drives the 7-stage pipeline
     │
     ├─ scanner/evidence.py     → Slither Python API → structured FunctionEvidence
     ├─ ai/triage.py + ai/provider.py (or ai/heuristic.py)
     ├─ graph/attack_paths.py + graph/finding_paths.py  (NetworkX)
     ├─ verification/templates.py + verification/runner.py  (Foundry + bubblewrap)
     └─ reports/builder.py
```

### Module map

| Path | Responsibility |
|------|----------------|
| `models.py` | Pydantic data model shared by every layer. Keeps static / AI / dynamic data in separate types (`Finding`, `Assessment`, `Verification`, `AttackPath`). |
| `scanner/evidence.py` | Runs Slither, resolves each detector result back to the real `Function` object, extracts `FunctionEvidence`, collects sources & contracts. |
| `scanner/orchestrator.py` | Runs the pipeline stages, updates progress, honours which stages are enabled. |
| `ai/provider.py` | `AIProvider` abstraction: `AnthropicProvider`, `OpenAIProvider`, `LocalProvider`. Stdlib HTTP only — no vendor SDK dependency. |
| `ai/triage.py` | Builds the prompt from evidence, calls the provider, **strictly validates** the JSON response (retries once, then degrades). |
| `ai/heuristic.py` | Deterministic rule-based fallback used when no provider is configured. Labelled `provider="heuristic"` so it is never shown as AI. |
| `graph/attack_paths.py` | Builds the NetworkX security graph; derives access-control escalation paths and one `auditlens-privilege-escalation` finding per direct path (`origin: auditlens-graph`). |
| `graph/finding_paths.py` | Per-finding reentrancy and unchecked-call paths. |
| `verification/templates.py` | Fixed Foundry test templates. The model supplies only parameters, never code. |
| `verification/runner.py` | Writes a throwaway Foundry project, runs `forge build` / `forge test --json` under bubblewrap + prlimit with a cleared environment, classifies each test from forge's JSON, records provenance. |
| `verification/impact.py` | Turns logged test values into impact measurements; omits anything not logged. |
| `verification/patch.py` | CEI patch generation, user-patch intake, patch validation (original vs patched, exploit + legitimate use + Slither recheck). |
| `ledger.py` | SQLite scan persistence and the hash-chained evidence ledger. |
| `bundle.py` | Proof bundle build, re-verification (integrity, ledger chain, re-execution) and exploit regression recheck. |
| `benchmark.py` | Deterministic regression benchmark (`python -m slither.tools.workbench.benchmark`). |
| `demo/benchmark/` | Patch fixtures: a hand-written fix and a deliberately bad "fix" that disables withdrawals. |
| `reports/builder.py` | Dashboard summary + Markdown report. |
| `api/app.py` | FastAPI routes; serves the SPA. |
| `api/store.py` | Scan lifecycle, upload validation, artifact storage, SQLite write-through, on-demand verify / patch / validate. |
| `frontend/` | Zero-build SPA (`index.html`, `style.css`, `app.js`). No bundler, no npm. |
| `demo/VulnerableBank.sol` | Intentionally vulnerable demo contract (reentrancy, missing access control, unchecked call). |

### Pipeline stages

1. **Contract ingestion** – validate and store uploaded sources.
2. **Compiler detection** – crytic-compile picks the solc version.
3. **Slither analysis** – run detectors, extract evidence.
4. **AI vulnerability triage** – assess each High/Medium/Low finding.
5. **Attack-path analysis** – build the graph, derive paths.
6. **Dynamic verification** – run exploit templates for reentrancy / access-control findings.
7. **Report generation** – finalise summary.

Each stage can be toggled from the upload screen (static analysis is always on).

---

## Install on a new machine

### Prerequisites

| Tool | Purpose | Required? |
|------|---------|-----------|
| Python ≥ 3.10 | Runs Slither + AuditLens | **Yes** |
| `solc` (via solc-select) | Compiles contracts for Slither | **Yes** |
| Foundry (`forge`, `anvil`) | Dynamic exploit verification | Optional (verification degrades to INCONCLUSIVE without it) |
| `bwrap` (bubblewrap) | Sandboxes exploit execution | Optional (verification runs without it, just unsandboxed) |
| A modern browser | The UI | **Yes** |

On Debian/Kali/Ubuntu, bubblewrap is `sudo apt install bubblewrap`.

### Step 1 — Get the code

```bash
git clone <your-fork-or-repo-url> AuditLens
cd AuditLens
```

> AuditLens is the Slither tree with the workbench tool added. If you cloned upstream Slither
> instead, copy `slither/tools/workbench/` and the `pyproject.toml` changes into it.

### Step 2 — Python environment

A virtualenv is **not relocatable** — always create it inside the final project directory.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[workbench]"     # Slither + fastapi, uvicorn, networkx, python-multipart
```

### Step 3 — Install solc

```bash
.venv/bin/pip install solc-select
.venv/bin/solc-select install 0.8.24
.venv/bin/solc-select use 0.8.24
```

(Slither auto-selects a matching solc per contract pragma when other versions are installed.)

### Step 4 — (Optional) Enable dynamic verification with Foundry

Without this, AuditLens still generates exploit tests but marks them `INCONCLUSIVE`.

```bash
# 4a. Install Foundry
curl -L https://foundry.paradigm.xyz | bash
~/.foundry/bin/foundryup

# 4b. Vendor forge-std so tests compile offline inside the sandbox
git clone --depth 1 https://github.com/foundry-rs/forge-std /tmp/forge-std
mkdir -p slither/tools/workbench/verification/vendor/forge-std
cp -r /tmp/forge-std/src slither/tools/workbench/verification/vendor/forge-std/

# 4c. Pre-download the solc Foundry needs (the sandbox has NO network)
cd /tmp/forge-std && forge build && cd -
```

AuditLens auto-detects `~/.foundry/bin`, so you do **not** need to add Foundry to your PATH.

### Step 5 — (Optional) Test dependencies

```bash
.venv/bin/pip install pytest pytest-xdist pytest-insta pytest-cov filelock deepdiff httpx
```

---

## Running AuditLens

```bash
cd AuditLens
PATH=$PWD/.venv/bin:$PATH .venv/bin/auditlens
```

Then open **http://127.0.0.1:8800**.

> The `PATH=$PWD/.venv/bin:$PATH` prefix puts the venv's `solc` shim on PATH so Slither can
> compile. Without it you'll see a "solc not found" warning.

`slither-workbench` is an alias for the same command.

### Options

```bash
.venv/bin/auditlens --host 0.0.0.0 --port 9000   # bind address / port
.venv/bin/auditlens --solc /path/to/solc          # explicit solc binary
.venv/bin/auditlens --data-dir ./auditlens-data   # scans, artifacts, ledger (auditlens.db)
```

By default data lives in `$XDG_DATA_HOME/auditlens` (usually `~/.local/share/auditlens`). Scans
and evidence survive restarts; a scan that was running when the server stopped is marked failed
("Interrupted").

---

## Using the workbench

The intended flow, matching the sidebar:

1. **Overview** — start here; click **▶ Run demo scan** or **Upload contract**.
2. **New Scan** — drag in `.sol`/`.vy` files (or use the demo). Choose which stages to run.
   The pipeline shows live progress ("7 findings discovered", "4 attack paths identified", …).
3. **Findings** — filter by severity / detector / exploitability / verification status. Expand
   a finding to see three clearly-separated blocks:
   - **Static finding (Slither)** — the raw detection + extracted evidence table.
   - **AI / Heuristic assessment** — classification, confidence bar, preconditions, evidence,
     candidate attack, remediation. Always labelled a hypothesis.
   - **Dynamic verification** — the sandbox result and on-chain evidence.
4. **Attack Paths** — interactive graph (colour-coded: attacker, entry point, vulnerable
   function, state mutation, external call, attacker-controlled) plus a step-by-step view.
   Click a node for its source and why it matters.
5. **Verification** — the step flow (hypothesis → test → compile → sandbox → result), run
   provenance (run ID, test + source hashes, sandboxed, forge version), measured impact,
   limitations, reproduction commands, a download of the generated test, the call trace and the
   raw forge output. **Re-run verification** records a new run in the ledger.
6. **Remediation** — guidance (Slither recommendation + AI suggestion, labelled), **Generate
   candidate patch** (reentrancy-eth) or **Write my own patch**, a diff marked *SUGGESTED*, and
   **Validate patch** with a per-check table.
7. **Source** — lightweight code viewer; the vulnerable line is highlighted, related lines
   dimmed, with an explanation panel.
8. **Report** — export Markdown / JSON, or print to PDF.
9. **Scans** — persisted scan history.

Each expanded finding shows a **Security evidence ledger** table (one row per evidence
category, with entry hashes and chain status) and buttons to move between finding, source,
attack path, verification and remediation without losing context.

Deep links work: `http://127.0.0.1:8800/#view=verify&scan=<id>&finding=<finding-id>`.

### The demo, end to end

Running the demo on `VulnerableBank.sol` produces (with Foundry installed):

- 7 static findings (High reentrancy, Medium unchecked call, Low missing zero-check, plus info).
- AI/heuristic flags the reentrancy as **likely exploitable**.
- 4 attack paths, including `withdraw()` reentrancy and `setOwner → owner → payFee/sweep`
  privilege escalation. The graph rule turns the two escalation paths into two High findings
  labelled *Static inference — AuditLens graph rule* (Slither itself only reports
  `missing-zero-check` on `setOwner`).
- Reentrancy dynamic verification: **VERIFIED** in ~0.7 s — contract drained from 5 ETH to 0,
  attacker balance 1 → 6 ETH, 5/5 re-entries succeeded, solvency invariant violated (5 ETH
  shortfall). Path `re-1` becomes *dynamically demonstrated*.
- Privilege escalation (differential test): `sweep()` / `payFee(1)` **revert** for the attacker,
  the attacker calls `setOwner(attacker)`, the same call then **succeeds** → **VERIFIED**.
  `sweep` moves the 5 ETH fixture to the attacker; `payFee` moves 1 wei (placeholder argument).
  Paths `ac-1` / `ac-2` become *dynamically demonstrated*.
- Generated patch: `balances[msg.sender] = 0;` moved above the call → **validated** (exploit
  blocked with re-entry attempted, legitimate use passes on original and patched, Slither no
  longer reports `withdraw()`).
- Generated access-check patch: `require(msg.sender == owner, "caller is not owner");` inserted
  in `setOwner` → **validated** (exploit blocked, the deployer can still hand ownership to a new
  address who can then use `sweep`, and the graph rule no longer derives the path).

---

## AI provider configuration

By default AuditLens uses the offline heuristic (shown as "AI: heuristic" in the top bar).
To use a real model, set environment variables before launching:

```bash
export WORKBENCH_AI_PROVIDER=anthropic        # anthropic | openai | local
export ANTHROPIC_API_KEY=sk-ant-...           # or OPENAI_API_KEY for openai
export WORKBENCH_AI_MODEL=claude-sonnet-5      # optional; sensible default per provider
export WORKBENCH_AI_BASE_URL=...               # optional; for proxies / local servers
.venv/bin/auditlens
```

| Provider | Env for key | Default model | Notes |
|----------|-------------|---------------|-------|
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-5` | Anthropic Messages API |
| `openai` | `OPENAI_API_KEY` | `gpt-4o` | Chat Completions, JSON mode |
| `local` | *(none)* | `llama3.1` | Any OpenAI-compatible server (Ollama, llama.cpp); set `WORKBENCH_AI_BASE_URL` |

The AI layer **only turns a prompt into text**. It never executes commands. Every response is
validated against the `Assessment` schema; malformed JSON triggers one retry, then falls back to
the heuristic assessment so a scan never fails because of the model.

---

## Dynamic verification & the sandbox

Verification is deliberately constrained:

1. **Templates, not model code.** `verification/templates.py` holds fixed Foundry test
   templates (reentrancy, access-control). The AI/heuristic layer supplies only structured
   *parameters* (function names, deposit amounts). It never provides Solidity or shell.
2. **Fixed argv.** `forge test` is invoked as a fixed argument list — never a shell string.
3. **Sandbox.** When `bwrap` is present, the test runs under bubblewrap with:
   - `--unshare-net` — no network at all.
   - read-only binds of `/usr`, the Foundry bin dir, the solc cache, and `~/.foundry`.
   - only the throwaway project directory is writable.
   - a fresh `/tmp` tmpfs (mounted before the workdir bind, so a workdir under `/tmp` is not
     shadowed).
4. **Limits.** 120-second wall-clock timeout; output truncated to 20 000 chars.
5. **Honest results.** If Foundry or `forge-std` or the solc cache is missing, the result is
   `INCONCLUSIVE` with the generated test shown — never a fabricated pass/fail.

6. **Cleared environment.** forge runs with a minimal env (`--clearenv` under bwrap, explicit
   `env=` otherwise), so server secrets such as `ANTHROPIC_API_KEY` cannot be read by contract
   code via `vm.envString`. `foundry.toml` pins `ffi = false` and `fs_permissions = []`.
   `prlimit` caps CPU time, file size, core dumps and open files. Tests verify all three.

Result states are derived from forge's JSON output, per test:

| Status | When |
|--------|------|
| `verified_exploit` | The exploit assertion passed (the security property was violated). |
| `not_verified` | The test failed on the template's `AUDITLENS_EXPLOIT_NOT_REPRODUCED` assertion **and** the attack path was exercised. |
| `inconclusive` | Unrelated revert, a privileged function callable *without* escalation (the escalation test cannot attribute access to the writer), an access-control call that reverted (cannot separate guard from precondition), the attack path was not exercised, no template applies, or Foundry is unavailable. |
| `verification_error` | Compile failure, `setUp()` failure, timeout, unparsable output, or missing test. |

A compile failure, timeout or broken fixture is never treated as evidence for or against a
vulnerability.

---

## Security model

AuditLens treats every uploaded contract and every generated test as untrusted:

- Uploads are validated by extension (`.sol`/`.vy`) and size-limited (2 MB/file).
- Artifacts are stored outside the application tree (system temp dir by default).
- The LLM cannot execute anything; it only returns text that is parsed and validated.
- Exploit tests run in the bubblewrap sandbox with no network and a minimal filesystem view.
- No AI-generated shell commands are ever executed.

---

## Testing

```bash
cd AuditLens
PATH=$PWD/.venv/bin:$PATH .venv/bin/python -m pytest tests/tools/workbench/ -p xdist -n0
```

- 95 tests: static analysis, evidence extraction, heuristic triage, attack paths and their
  evidence annotation, outcome classification (pass / property held / unrelated revert / setUp
  failure / compile error / timeout), sandbox isolation (env cleared, ffi and fs reads blocked),
  impact measurement, patch generation + all four validation outcomes, ledger tamper detection
  and persistence, API input validation, the full API workflow across a restart, reports, and
  SC01 escalation (graph-derived findings, differential exploit, "callable without escalation"
  is inconclusive, guard patch and its refusal, four validation outcomes), proof bundles
  (reproduce, modified source, re-hashed source caught by claim digest, edited ledger, changed
  claim outcome, unsafe/unlisted members, invalid/oversized zip), recheck (fixed / bad fix /
  original / renamed contract), the scorecard, CLI exit codes, and root-cause scoring.
- Tests that need `solc` or `forge` are auto-skipped when those tools are absent.
- **`-p xdist -n0` is required**: the repo's root `conftest.py` defines xdist hooks, so the
  plugin must be loaded (but `-n0` keeps it single-process). Do **not** pass `-p no:xdist` or
  `-p no:cacheprovider`.

---

## Extending AuditLens

To add a new vulnerability class:

1. **Evidence** — map the Slither detector(s) to a category in `CATEGORY_BY_DETECTOR`
   (`scanner/evidence.py`).
2. **Attack path** — add a path builder in `graph/finding_paths.py` (or a graph rule in
   `graph/attack_paths.py`).
3. **Verification (optional)** — add a template to `verification/templates.py` and register it
   in `TEMPLATE_BUILDERS`, then include the category in the orchestrator's verification targets.
4. **Prompt** — no change needed; triage is category-agnostic and reads the evidence.

The design favours a few deeply-implemented classes (reentrancy, access control, unchecked
calls) over many shallow ones.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `bad interpreter: .../.venv/bin/python3: no such file` | The project folder was moved/renamed; the venv hardcodes paths | `rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -e ".[workbench]"` |
| `auditlens: command not found` / missing script | Package installed before the entry point existed | Reinstall: `.venv/bin/pip install -e .` |
| "solc not found" warning | venv's solc shim not on PATH | Prefix with `PATH=$PWD/.venv/bin:$PATH`, or install solc-select |
| Verification always `INCONCLUSIVE` | Foundry / forge-std / solc cache missing | Follow [Step 4](#step-4--optional-enable-dynamic-verification-with-foundry) |
| Verification `INCONCLUSIVE` only inside the sandbox | solc not pre-downloaded (sandbox has no network) | Run `forge build` once outside the sandbox to cache solc |
| `ModuleNotFoundError: fastapi` | Installed without extras | `.venv/bin/pip install -e ".[workbench]"` |
| Tests error with `unknown hook 'pytest_configure_node'` | xdist plugin disabled | Use `-p xdist -n0`, install `pytest-xdist` |

---

## API reference

All endpoints are served by the same process as the UI.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/status` | AI provider + Foundry availability |
| `POST` | `/api/scans` | Upload files (`multipart`) + `options` JSON; returns `{id}` |
| `POST` | `/api/scans/demo` | Scan the bundled demo contract; returns `{id}` |
| `GET` | `/api/scans` | List scans in this session |
| `GET` | `/api/scans/{id}` | Full scan state (findings, paths, stages, summary) |
| `GET` | `/api/scans/{id}/report.md` | Markdown report |
| `GET` | `/api/scans/{id}/report.json` | Full JSON report |
| `DELETE` | `/api/scans/{id}` | Delete a scan, its artifacts and ledger entries |
| `GET` | `/api/scans/{id}/ledger` | All ledger entries + chain verification |
| `GET` | `/api/scans/{id}/findings/{fid}/evidence` | Evidence record (static / AI / execution / remediation / paths) |
| `GET` | `/api/scans/{id}/findings/{fid}/test.sol` | The generated exploit test |
| `POST` | `/api/scans/{id}/findings/{fid}/verify` | Re-run verification (409 while busy or scan unfinished) |
| `POST` | `/api/scans/{id}/findings/{fid}/patch` | Generate a patch, or JSON `{"file", "source"}` to supply one |
| `POST` | `/api/scans/{id}/findings/{fid}/patch/validate` | Validate the current patch |

`report.json` keeps every previous top-level field and adds `report_version` (2),
`generated_at`, `summary` and `evidence_ledger` (`chain` + `entries`).

`options` is a JSON object: `{"static_analysis": true, "ai_triage": true,
"attack_paths": true, "dynamic_verification": true}`.

---

---

## Proof bundles & regression checks

```bash
# Report page → Download proof bundle (or GET /api/scans/<id>/bundle.zip), then anywhere:
auditlens verify-bundle auditlens-<id>-proof-bundle.zip           # REPRODUCED: 11/11 claims
auditlens verify-bundle bundle.zip --json                          # machine-readable
auditlens recheck bundle.zip path/to/new/contracts/                # ALL_BLOCKED / REGRESSION
```

**Bundle layout:** `manifest.json` (file hashes, claims, ledger head), `sources/original/`,
`sources/patch-<id>/`, `tests/<sha>.t.sol`, `ledger.json`, `report.md`. A *claim* is one
recorded run: "test T against source set S produced outcome O (run R, ledger entry E)".

**`verify-bundle` checks, in order:** every file's SHA-256 against the manifest; no unlisted or
unsafe (`..`, absolute) paths; the ledger chain; each claim's test hash and source digest; that
each claim's run is recorded in the ledger. Any failure → `TAMPERED` and nothing is executed.
Otherwise every distinct (sources, test) pair is re-run in the sandbox and outcomes compared →
`REPRODUCED` or `MISMATCH`. Without Foundry → `INTEGRITY_ONLY`. Exit code 0 only for
`REPRODUCED`. Size, member-count and expanded-size limits guard against zip bombs; members
are read in memory, never extracted by name.

**`recheck`** runs the exploits that originally *passed* against the new sources:
`exploitable` (regression, exit 1), `blocked` (assertion failed with the attack exercised),
`inconclusive` (exit 2 — e.g. a renamed contract no longer compiles; never reported as safe).
In the UI (Report → *Recheck a new version…*) results are also written to the ledger as
`regression_check` entries.

**What this proves:** that these tests, on these sources, still behave as recorded on the
verifier's machine. It does not prove the tests are the right tests.

---

## Evidence ledger

Stored in `<data-dir>/auditlens.db` (stdlib `sqlite3`, no new dependency). Two tables: `scans`
(full scan JSON, written on every update) and `entries` (append-only evidence records).

Entry kinds: `static_fact`, `ai_hypothesis`, `execution`, `remediation`, `attack_path`,
`scan_event`. Failed and inconclusive runs are recorded, not dropped. Each entry stores the
SHA-256 of its canonical JSON payload, the previous entry's hash and its own hash (chained per
scan). Execution entries carry the run ID, test SHA-256 and source digest, so a report can be
matched to the exact test bytes and sources that were executed; the UI flags a displayed run
that is missing from the ledger.

**Integrity guarantee, stated plainly:** `GET /api/scans/{id}/ledger` recomputes the chain and
detects corruption or edits that do not rewrite every later hash. Anyone who can write the DB
file can rewrite the whole chain consistently. A hash shows two artifacts are identical, not
that either is true.

---

## Patch & regression validation

1. **Propose.** For reentrancy-eth, the state writes Slither reports *after* the external call
   are moved directly before it. The mover refuses when a write is not a single statement or
   uses a value produced by/after the call (e.g. `ok`). Any finding can instead take a
   user-supplied full file.
2. **Validate** in `<data-dir>/scans/<id>/patches/...` — two throwaway projects (original,
   patched) with byte-identical tests:

| Check | Required for `validated` |
|-------|--------------------------|
| Patched project compiles | yes (else `error`) |
| Exploit reproduces on original | yes (else `inconclusive` — the test proves nothing) |
| Legitimate use passes on original | yes (else `inconclusive` — invalid baseline) |
| Exploit blocked on patched: fails on the security assertion, re-entry attempted | yes (passes → `failed`; other failure / not exercised → `inconclusive`) |
| Legitimate use passes on patched | yes (else `failed`) |
| Static re-analysis no longer reports it (Slither detector, or the AuditLens graph rule for escalation findings) | reported only, never gates (static analysis can be silenced by breaking the code) |

The bundled `demo/benchmark/withdraw_disabled.sol` shows why: it blocks the exploit and silences
Slither, but validation reports **failed** because legitimate withdrawals break.

---

## Benchmark

```bash
PATH=$PWD/.venv/bin:$PATH .venv/bin/python -m slither.tools.workbench.benchmark          # table
PATH=$PWD/.venv/bin:$PATH .venv/bin/python -m slither.tools.workbench.benchmark --json   # JSON
```

Seventeen expected-vs-actual cases on the bundled corpus; exits non-zero on any mismatch. Last
local run (forge 1.8.3, bubblewrap, solc 0.8.24): **17 passed, 0 failed, ~30 s total**.

| Case | Expected | Observed |
|------|----------|----------|
| Full pipeline on demo | done | done (7 Slither + 2 graph-rule findings, ~2.5 s) |
| SC05 reentrancy-eth exploit | verified, exercised | verified, 5/5 re-entries, 5 ETH shortfall |
| SC01 escalation `setOwner → sweep` | verified, exercised | verified, attacker 0 → 5 ETH |
| SC01 escalation `setOwner → payFee` | verified, exercised | verified, 1 wei moved |
| Slither-only baseline | same 7 Slither findings, 0 executed | same; full pipeline adds 2 and executes 3 |
| SC05 generated CEI patch | validated | validated (~1.6 s) |
| SC05 hand-written fix (negative control) | validated | validated |
| SC05 fix that disables `withdraw()` | failed | failed (legitimate use reverts) |
| SC05 patch with a syntax error | error | error |
| SC01 generated access-check patch | validated | validated |
| SC01 hand-written fix | validated | validated |
| SC01 patch leaving `setOwner` unguarded | failed | failed (exploit still succeeds) |
| SC01 patch that freezes ownership | failed | failed (legitimate handover reverts; graph rule silent) |
| Proof bundle re-execution | reproduced | reproduced (3 exploit claims, ~2 s) |
| Tampered bundle (one source line changed) | tampered | tampered, nothing executed |
| Recheck: hand-written fix | all_blocked | all 3 proven exploits blocked |
| Recheck: original code | regression | 3 exploitable |

The Slither comparison is deliberately narrow: identical findings, plus execution evidence for
the findings a template covers. No precision/recall or false-positive rates are claimed — that
needs a labelled corpus.

---

## Limitations

- OWASP SC coverage with execution evidence: **SC05** reentrancy-eth (deposit/withdraw with no
  arguments) and **SC01** access control — direct escalation paths (attacker → unprotected
  writer → guard variable → privileged function → sink, all in one contract, no-argument
  constructor) and unprotected privileged functions (`suicidal`, `arbitrary-send-eth`, …).
  SC06 (unchecked calls) and the rest remain static warnings. SC02 / SC03 / SC07 (oracles,
  logic, flash loans) cannot be templated generically.
- Escalation templates use placeholder arguments; impact can be tiny (`payFee(1)` moves 1 wei)
  and is reported as measured.
- The guard patch requires the guard to be a plain `address` variable and the writer's opening
  brace at a line end; otherwise it refuses and asks for a user patch.
- Measured impact uses fixture amounts (5 ETH victim, 1 ETH attacker) — not production losses.
- No AI-generated test code is ever executed; the AI layer only produces hypotheses.
- Without `bwrap`, tests run with a cleared environment and resource limits but no network or
  filesystem isolation (`sandboxed: NO` is shown on the run).
- Verification and validation requests run synchronously (~1–2 s each on the demo).
- Ledger hashes are tamper-evident only against partial edits (see above).

---

## Finals demo script

1. **Overview → Run demo scan.** Narrate the pipeline: Slither (7 findings) → heuristic triage
   → 4 attack paths → 1 exploit verified.
2. **Findings → High: Reentrancy.** Show the three separate blocks: static fact + code, the
   hypothesis (labelled), execution evidence with the impact table (5 ETH → 0, solvency
   invariant *violated*). Point at the ledger table: four categories, entry hashes, intact chain.
   On the Remediation page, point at the drain chart: the original run falls 5 → 0 ETH below
   the "owed to honest depositor" line; the patched run stays flat. Overview shows the AI
   scorecard: 3 hypotheses confirmed by execution, 2 untested — the AI is graded, not trusted.
3. **Attack path.** `re-1` is *dynamically demonstrated* by a named run; `uc-2` (unchecked
   call) stays a *static hypothesis* — "connected nodes are not proof."
4. **SC01 escalation.** Open *Privilege escalation: setOwner(address) → sweep()*: labelled as an AuditLens graph-rule inference, not a Slither result.
   Show the differential impact row (attacker's `sweep()` reverted → succeeded) and 0 → 5 ETH.
   Generate and validate the access-check patch.
5. **Verification.** Run provenance (run ID, test SHA-256, sandboxed), the call trace with five
   nested `withdraw()` calls, reproduction commands. Click **Re-run verification** live.
6. **Remediation.** **Generate candidate patch** → diff marked SUGGESTED → **Validate patch** →
   six checks, verdict *validated*, tested properties and limitations.
7. **Honesty beat.** **Write my own patch**, paste `demo/benchmark/withdraw_disabled.sol`,
   validate → **failed**: exploit "blocked", Slither silent, but legitimate withdrawals break.
8. **Proof, live.** Report → **Download proof bundle**, then **Verify a bundle…** with it →
   *BUNDLE REPRODUCED 11/11*. In a terminal, change one character in
   `sources/original/VulnerableBank.sol` inside the zip and run `auditlens verify-bundle` →
   *TAMPERED*. "Don't trust our report — re-execute it."
9. **Regression memory.** **Recheck a new version…** with `demo/benchmark/fixed.sol` → *all
   proven exploits still blocked*; with `withdraw_disabled.sol` → *REGRESSION* (the escalation
   is still open). Mention the CI exit code.
10. **Report → Download Markdown.** Show run IDs, hashes, the patch diff and the ledger head in
   the export.

---

*AuditLens is built on Slither by Trail of Bits. The novelty is the integration and workflow —
Detect → Understand → Trace → Verify → Fix → Prove — not a claim that the LLM detects
vulnerabilities on its own.*

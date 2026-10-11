"""Report and dashboard-summary generation from a completed scan."""

from pydantic import BaseModel

from slither.tools.workbench.models import (
    Finding,
    PatchStatus,
    Scan,
    Verification,
    VerificationStatus,
)

EXPLOITABLE = {"likely_exploitable", "possibly_exploitable"}

EVIDENCE_LEGEND = [
    "**Static fact** — directly reported by a Slither detector or read from the source.",
    "**AI hypothesis** — an interpretation by a model or the heuristic rules; requires validation.",
    "**Execution evidence** — the recorded outcome of an actual sandboxed Foundry test run.",
    "**Remediation evidence** — results of validating a candidate patch in a throwaway workspace.",
]

GLOBAL_LIMITATIONS = [
    "Measured impact comes from local test fixtures with fixed amounts; it is not an estimate "
    "of production losses.",
    "Attack paths marked static-hypothesis are graph connectivity only, not demonstrated exploits.",
    "A validated patch addresses only the tested properties; it does not make the contract "
    "secure in general.",
    "Findings without an applicable exploit template remain static warnings.",
]


# (unverified, verified exploit) points per root cause. Verification raises a root cause's
# weight once; it is not charged as an extra finding.
SCORE_WEIGHTS = {"High": (20, 30), "Medium": (8, 15), "Low": (3, 6)}


class ScoreDeduction(BaseModel):
    points: int
    impact: str
    verified: bool
    root_cause: str
    finding_ids: list[str]
    titles: list[str]


class ScanSummary(BaseModel):
    security_score: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    ai_confirmed: int
    potential_false_positives: int
    verified_exploits: int
    total_findings: int
    attack_paths: int
    not_reproduced: int = 0
    undetermined: int = 0
    patches_validated: int = 0
    ai_scorecard: dict[str, int] = {}
    score_breakdown: list[ScoreDeduction] = []


def _impact_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Optimization": 0}
    for f in findings:
        counts[f.impact] = counts.get(f.impact, 0) + 1
    return counts


def _count(findings: list[Finding], *statuses: VerificationStatus) -> int:
    return sum(1 for f in findings if f.verification.status in statuses)


DISMISSED = {"unlikely_exploitable", "likely_false_positive"}


def hypothesis_scorecard(findings: list[Finding]) -> dict[str, int]:
    """Grade AI/heuristic predictions against execution; anything not executed is untested."""
    card = {"confirmed": 0, "refuted": 0, "missed": 0, "correctly_dismissed": 0, "untested": 0}
    for f in findings:
        if f.assessment is None:
            continue
        predicted = f.assessment.classification.value
        status = f.verification.status
        decided = status in (VerificationStatus.VERIFIED, VerificationStatus.NOT_VERIFIED)
        if not decided or (predicted not in EXPLOITABLE and predicted not in DISMISSED):
            card["untested"] += 1
        elif predicted in EXPLOITABLE:
            card["confirmed" if status is VerificationStatus.VERIFIED else "refuted"] += 1
        else:
            card["missed" if status is VerificationStatus.VERIFIED else "correctly_dismissed"] += 1
    return card


def _root_cause(finding: Finding) -> tuple[str, str]:
    """Findings of one vulnerability class in one function share a root cause and one fix."""
    return finding.category or finding.detector, finding.function or finding.id


def _weight(finding: Finding) -> int:
    unverified, verified = SCORE_WEIGHTS.get(finding.impact, (0, 0))
    return verified if finding.verification.status is VerificationStatus.VERIFIED else unverified


def score_breakdown(findings: list[Finding]) -> list[ScoreDeduction]:
    """One deduction per root cause, weighted by its most severe (and best evidenced) finding."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(_root_cause(finding), []).append(finding)
    deductions = []
    for (kind, where), members in groups.items():
        worst = max(members, key=_weight)
        if _weight(worst) == 0:
            continue
        deductions.append(
            ScoreDeduction(
                points=_weight(worst),
                impact=worst.impact,
                verified=worst.verification.status is VerificationStatus.VERIFIED,
                root_cause=f"{kind} in {where}" if where != worst.id else kind,
                finding_ids=[f.id for f in members],
                titles=[f.title for f in members],
            )
        )
    return sorted(deductions, key=lambda d: -d.points)


def build_summary(scan: Scan) -> ScanSummary:
    counts = _impact_counts(scan.findings)
    ai_confirmed = sum(
        1
        for f in scan.findings
        if f.assessment and f.assessment.classification.value in EXPLOITABLE
    )
    false_positives = sum(
        1
        for f in scan.findings
        if f.assessment and f.assessment.classification.value == "likely_false_positive"
    )
    verified = _count(scan.findings, VerificationStatus.VERIFIED)
    breakdown = score_breakdown(scan.findings)
    return ScanSummary(
        security_score=max(0, 100 - sum(d.points for d in breakdown)),
        score_breakdown=breakdown,
        critical=verified,
        high=counts["High"],
        medium=counts["Medium"],
        low=counts["Low"],
        informational=counts["Informational"],
        ai_confirmed=ai_confirmed,
        potential_false_positives=false_positives,
        verified_exploits=verified,
        total_findings=len(scan.findings),
        attack_paths=len(scan.attack_paths),
        not_reproduced=_count(scan.findings, VerificationStatus.NOT_VERIFIED),
        undetermined=_count(
            scan.findings, VerificationStatus.INCONCLUSIVE, VerificationStatus.ERROR
        ),
        ai_scorecard=hypothesis_scorecard(scan.findings),
        patches_validated=sum(
            1
            for f in scan.findings
            if f.remediation and f.remediation.status is PatchStatus.VALIDATED
        ),
    )


def _where(finding: Finding) -> str:
    loc = finding.location
    if loc is None:
        return "?"
    return f"{loc.file}:{loc.lines[0]}" if loc.lines else loc.file


def _ai_lines(finding: Finding) -> list[str]:
    a = finding.assessment
    if a is None:
        return []
    source = "AI" if a.provider not in ("heuristic", "") else "Heuristic"
    lines = [
        f"**AI hypothesis ({source}, {a.model or a.provider}):** {a.classification.value} "
        f"(confidence {a.confidence}%) — requires validation.",
        "",
        a.why_it_matters or a.summary,
        "",
    ]
    if a.preconditions:
        lines += ["Assumptions / preconditions:"] + [f"- {p}" for p in a.preconditions] + [""]
    if a.remediation:
        lines += [f"**Suggested remediation:** {a.remediation}", ""]
    return lines


def _impact_table(v: Verification) -> list[str]:
    if not v.impact:
        return []
    rows = ["| Measurement | Before | After | Change | Violated |", "|---|---|---|---|---|"]
    for m in v.impact:
        violated = "" if m.violated is None else ("yes" if m.violated else "no")
        rows.append(
            f"| {m.label} | {m.before or ''} | {m.after or ''} | {m.delta or ''} | {violated} |"
        )
    return [
        "Measured impact (observed in the local test fixture, not a production estimate):",
        "",
        *rows,
        "",
    ]


def _execution_lines(finding: Finding) -> list[str]:
    v = finding.verification
    if v.status is VerificationStatus.NOT_RUN:
        return ["**Execution evidence:** none — no test was run for this finding.", ""]
    lines = [f"**Execution evidence:** `{v.status.value}` — {v.summary}", ""]
    if v.run:
        r = v.run
        lines += [
            f"- Run `{r.run_id}`: `{r.test_file}` → `{r.test_contract}::{r.test_function}`",
            f"- Outcome `{r.outcome}`, exit code {r.exit_code}, {r.duration_s}s, "
            f"sandboxed: {'yes' if r.sandboxed else 'NO'}, {r.forge_version or 'forge'}",
            f"- Test SHA-256 `{r.test_sha256}`",
            f"- Sources SHA-256 `{r.source_sha256}`",
        ]
        if v.attack_exercised is not None:
            lines.append(f"- Attack path exercised: {'yes' if v.attack_exercised else 'no'}")
        lines.append("")
    lines += _impact_table(v)
    if v.reproduction:
        lines += ["Reproduction:", "", "```bash", *v.reproduction, "```", ""]
    if v.limitations:
        lines += ["Limitations:"] + [f"- {item}" for item in v.limitations] + [""]
    return lines


def _remediation_lines(finding: Finding) -> list[str]:
    p, r = finding.patch, finding.remediation
    if p is None:
        return []
    lines = [
        f"**Remediation evidence:** candidate patch `{p.id}` ({p.origin}, {p.strategy}) — "
        f"suggested, never applied to the original files.",
        "",
        p.description,
        "",
        "```diff",
        p.diff.rstrip(),
        "```",
        "",
    ]
    if r is None:
        return lines + ["Patch not yet validated.", ""]
    lines += [
        f"Validation `{r.id}`: **{r.status.value}** — {r.summary}",
        "",
        "| Check | Status | Detail |",
        "|---|---|---|",
    ]
    for c in r.checks:
        detail = c.detail.splitlines()[0][:160] if c.detail else ""
        run = f" (run `{c.run.run_id}`)" if c.run else ""
        lines.append(f"| {c.name} | {c.status} | {detail}{run} |")
    lines += ["", "Tested properties:"] + [f"- {t}" for t in r.tested_properties]
    lines += ["", "Limitations:"] + [f"- {t}" for t in r.limitations] + [""]
    return lines


def _finding_section(
    finding: Finding, scan: Scan | None = None, entries: list[dict] | None = None
) -> str:
    lines = [f"### {finding.impact} — {finding.title} (`{finding.detector}`)", ""]
    if finding.function:
        lines.append(f"**Location:** `{finding.function}` at {_where(finding)}")
    source = (
        "AuditLens graph rule over Slither data"
        if finding.origin == "auditlens-graph"
        else "Slither"
    )
    lines += ["", f"**Static fact ({source}):**", "", finding.description, ""]
    lines += _ai_lines(finding)
    if scan:
        paths = [p for p in scan.attack_paths if finding.id in p.finding_ids]
        if paths:
            lines += [
                "**Attack paths:** " + ", ".join(f"`{p.id}` ({p.evidence_status})" for p in paths),
                "",
            ]
    lines += _execution_lines(finding)
    lines += _remediation_lines(finding)
    own = [e for e in entries or [] if e.get("finding_id") == finding.id]
    if own:
        lines += (
            ["Ledger entries:"]
            + [f"- #{e['seq']} {e['kind']} `{e['entry_hash'][:16]}…`" for e in own]
            + [""]
        )
    return "\n".join(lines)


def _paths_section(scan: Scan) -> list[str]:
    if not scan.attack_paths:
        return []
    out = ["## Attack Paths", ""]
    for path in scan.attack_paths:
        out += [
            f"### {path.title}",
            "",
            f"Evidence status: **{path.evidence_status}** — {path.evidence_note}",
            "",
        ]
        if path.patch_status:
            out += [f"Patch validation for the linked finding: {path.patch_status}", ""]
        out += [f"{i}. {s}" for i, s in enumerate(path.narrative, 1)] + [""]
    return out


def _ledger_section(chain: dict | None, entries: list[dict]) -> list[str]:
    if chain is None:
        return []
    return [
        "## Evidence Ledger",
        "",
        f"- Entries: {chain['entries']}; chain valid: **{chain['valid']}**",
        f"- Chain head: `{chain['head']}`",
        f"- Integrity guarantee: {chain['guarantee']}",
        "",
        f"Entries referenced in this report: {len(entries)}.",
        "",
    ]


def build_markdown_report(
    scan: Scan, entries: list[dict] | None = None, chain: dict | None = None
) -> str:
    summary = build_summary(scan)
    entries = entries or []
    out = [
        f"# Security Report — {scan.name}",
        "",
        "## Executive Summary",
        "",
        f"- Security score: **{summary.security_score}/100**",
        f"- Findings: {summary.total_findings} "
        f"(High {summary.high}, Medium {summary.medium}, Low {summary.low})",
        f"- AI-flagged exploitable (hypotheses): {summary.ai_confirmed}",
        f"- Verified exploits (executed): {summary.verified_exploits}; "
        f"not reproduced: {summary.not_reproduced}; "
        f"inconclusive/error: {summary.undetermined}",
        f"- Patches validated: {summary.patches_validated}",
        "- AI hypothesis scorecard (graded against execution): "
        + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in summary.ai_scorecard.items()),
        f"- Attack paths identified: {summary.attack_paths}",
        f"- Compiler: {scan.compiler}",
        "",
        "> AI assessments are hypotheses. Only findings marked "
        "*verified_exploit* were dynamically reproduced.",
        "",
        "## Score Breakdown",
        "",
        "One deduction per root cause (vulnerability class × function); a verified exploit "
        "raises that root cause's weight instead of counting twice. Patches only change the "
        "score once the fixed code is scanned.",
        "",
        "| Points | Root cause | Severity | Evidence | Findings |",
        "|---|---|---|---|---|",
        *[
            f"| −{d.points} | {d.root_cause} | {d.impact} | "
            f"{'verified exploit' if d.verified else 'static'} | {', '.join(d.titles)} |"
            for d in summary.score_breakdown
        ],
        "",
        "## Evidence Classification",
        "",
        *[f"- {item}" for item in EVIDENCE_LEGEND],
        "",
        "## Contracts",
        "",
    ]
    out += [f"- `{c.name}` ({c.kind}) — {c.file}" for c in scan.contracts]
    out += ["", "## Findings", ""]
    out += [_finding_section(f, scan, entries) for f in scan.findings if f.impact != "Optimization"]
    out += _paths_section(scan)
    out += ["## Limitations and Remaining Uncertainty", ""]
    out += [f"- {item}" for item in GLOBAL_LIMITATIONS] + [""]
    out += _ledger_section(chain, entries)
    return "\n".join(out)

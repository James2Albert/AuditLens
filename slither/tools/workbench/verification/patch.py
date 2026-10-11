"""Candidate remediation patches and their validation.

Generation is deliberately narrow: for a reentrancy-eth finding, the state writes that
Slither reports *after* the external call are moved to just before it
(checks-effects-interactions). Anything the mover cannot prove safe is refused, and the
user may supply their own patched file instead.

Validation never touches the user's files. It runs the *same* exploit test (same bytes,
same hash) and a legitimate-use regression test against both the original and the
patched sources, then re-runs Slither on the patched sources. A patch is only VALIDATED
when the exploit reproduces on the original, is blocked on the patch for the asserted
reason with the attack path exercised, and legitimate use passes on both.
"""

import difflib
import re
import time
import uuid
from pathlib import Path

from slither.tools.workbench.models import (
    CheckResult,
    Finding,
    PatchProposal,
    PatchStatus,
    PatchValidation,
)
from slither.tools.workbench.graph.attack_paths import (
    access_control_paths,
    build_graph,
    escalation_findings,
)
from slither.tools.workbench.scanner.evidence import build_findings, run_slither, source_ref
from slither.tools.workbench.verification.runner import (
    SuiteRun,
    TestResult,
    build_run,
    execute_suite,
    first_error,
    foundry_available,
    sha256_text,
)
from slither.tools.workbench.verification.templates import (
    ExploitTemplate,
    RegressionTemplate,
    ESCALATION_DETECTOR,
    build_template,
    regression_template,
)

MAX_PATCH_BYTES = 2_000_000
DECLARATION = re.compile(
    r"\b(?:bool|u?int\d*|address(?:\s+payable)?|bytes\d*|string)\s+"
    r"(?:memory\s+|storage\s+|calldata\s+)?(\w+)"
)
IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")


def _make_proposal(
    finding: Finding,
    file: str,
    original: str,
    patched: str,
    origin: str,
    strategy: str,
    description: str,
) -> PatchProposal:
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{file}",
            tofile=f"b/{file}",
        )
    )
    return PatchProposal(
        id=sha256_text(f"{finding.id}:{patched}")[:12],
        finding_id=finding.id,
        origin=origin,
        strategy=strategy,
        description=description,
        file=file,
        original_sha256=sha256_text(original),
        patched_sha256=sha256_text(patched),
        diff=diff,
        patched_source=patched,
    )


def _cei_lines(finding: Finding, lines: list[str]) -> tuple[int, list[int]] | str:
    """(call line, write lines to move) or a reason why moving them is not provably safe."""
    calls = [
        r
        for r in finding.related
        if r.role in ("external_calls", "external_calls_sending_eth") and r.lines
    ]
    writes = [r for r in finding.related if r.role == "variables_written" and r.lines]
    if not calls or not writes:
        return "Slither did not report both the external call and the late state write."
    call_line = min(r.lines[0] for r in calls)
    write_lines = sorted({ln for r in writes for ln in r.lines if ln > call_line})
    body = (
        set(finding.evidence.source.lines)
        if finding.evidence and finding.evidence.source
        else set()
    )
    if not write_lines or not set(write_lines) <= body or max(write_lines) > len(lines):
        return "The late state writes are not inside the reported function body."
    declared = set(DECLARATION.findall("".join(lines[call_line - 1 : max(write_lines) - 1])))
    for ln in write_lines:
        stmt = lines[ln - 1].strip()
        if not stmt.endswith(";") or "{" in stmt or "}" in stmt:
            return f"Line {ln} is not a single simple statement; refusing to move it."
        if set(IDENTIFIER.findall(stmt)) & declared:
            return f"Line {ln} uses a value produced by or after the external call."
    return call_line, write_lines


def _guard_patch(finding: Finding, sources: dict[str, str]) -> tuple[PatchProposal | None, str]:
    """Insert `require(msg.sender == <guard>)` as the first statement of the writer."""
    guard = next((r.label for r in finding.related if r.role == "guard_variable"), None)
    file = finding.location.file if finding.location else ""
    body = finding.evidence.source.lines if finding.evidence and finding.evidence.source else []
    if guard is None or file not in sources or not body:
        return None, "The guard variable or the writer's source location was not captured."
    original = sources[file]
    declared = rf"\baddress\b(\s+payable)?(\s+(public|private|internal))*\s+{re.escape(guard)}\b"
    if not re.search(declared, original):
        return None, (
            f"`{guard}` is not declared as a plain address, so a msg.sender "
            "comparison would not be a faithful fix. Supply a patch instead."
        )
    lines = original.splitlines(keepends=True)
    header = next((ln for ln in body if "{" in lines[ln - 1]), None)
    if header is None or not lines[header - 1].rstrip().endswith("{") or header >= len(lines):
        return None, "The writer's opening brace is not on its own line end; refusing to edit."
    outer = re.match(r"\s*", lines[header - 1]).group(0)
    inner = re.match(r"\s*", lines[header]).group(0)
    indent = inner if len(inner) > len(outer) else outer + "    "
    check = f'{indent}require(msg.sender == {guard}, "caller is not {guard}");\n'
    patched = "".join(lines[:header] + [check] + lines[header:])
    return _make_proposal(
        finding,
        file,
        original,
        patched,
        origin="generated-template",
        strategy="add-access-check",
        description=(
            f"Require msg.sender to be the current `{guard}` in {finding.function}, so only "
            f"the existing role holder can reassign `{guard}`."
        ),
    ), ""


AUTO_PATCHES = {"reentrancy-eth", ESCALATION_DETECTOR}


def propose_patch(finding: Finding, sources: dict[str, str]) -> tuple[PatchProposal | None, str]:
    """Return (proposal, "") or (None, reason the patch could not be generated)."""
    if finding.detector == ESCALATION_DETECTOR:
        return _guard_patch(finding, sources)
    if finding.detector != "reentrancy-eth":
        return None, (
            "Automatic patches are only generated for reentrancy-eth and privilege-escalation "
            f"findings. Supply a patched file to validate a fix for '{finding.detector}'."
        )
    file = finding.location.file if finding.location else ""
    if file not in sources:
        return None, "The finding's source file was not captured."
    original = sources[file]
    lines = original.splitlines(keepends=True)
    located = _cei_lines(finding, lines)
    if isinstance(located, str):
        return None, located
    call_line, write_lines = located
    indent = re.match(r"\s*", lines[call_line - 1]).group(0)
    moved = [indent + lines[ln - 1].strip() + "\n" for ln in write_lines]
    kept = [line for number, line in enumerate(lines, 1) if number not in write_lines]
    patched = "".join(kept[: call_line - 1] + moved + kept[call_line - 1 :])
    statements = ", ".join(f"`{lines[ln - 1].strip()}`" for ln in write_lines)
    return _make_proposal(
        finding,
        file,
        original,
        patched,
        origin="generated-template",
        strategy="checks-effects-interactions",
        description=(
            f"Move {statements} above the external call on line {call_line} so state "
            f"is final before control leaves {finding.function}."
        ),
    ), ""


def user_patch(finding: Finding, sources: dict[str, str], file: str, source: str) -> PatchProposal:
    if file not in sources:
        raise ValueError(
            f"'{file}' is not a source file of this scan; choose one of: "
            f"{', '.join(sorted(sources))}"
        )
    if len(source.encode()) > MAX_PATCH_BYTES:
        raise ValueError(f"Patched source exceeds {MAX_PATCH_BYTES} bytes")
    if source == sources[file]:
        raise ValueError("Patched source is identical to the original")
    return _make_proposal(
        finding,
        file,
        sources[file],
        source,
        origin="user-supplied",
        strategy="user-supplied",
        description="Patch supplied by the user.",
    )


def _test_check(
    name: str,
    suite: SuiteRun,
    template: ExploitTemplate | RegressionTemplate,
    sources: dict[str, str],
    want: str,
) -> tuple[CheckResult, TestResult]:
    result = suite.result(template.test_file, template.test_contract, template.test_function)
    run = build_run(
        suite,
        template.test_file,
        template.test_contract,
        template.test_function,
        template.source,
        sources,
        result,
    )
    status = "pass" if result.outcome == want else "fail"
    if result.outcome in ("compile_error", "timeout", "infra_error", "missing", "setup_failed"):
        status = "error"
    detail = f"outcome: {result.outcome}" + (
        f" — {result.reason.splitlines()[0][:240]}" if result.reason else ""
    )
    return (
        CheckResult(
            name=name, status=status, detail=detail, run=run, observations=result.observations
        ),
        result,
    )


def _still_reported(finding: Finding, slither, results: list[dict], root: Path) -> bool:
    if finding.detector == ESCALATION_DETECTOR:
        graph = build_graph(slither)
        paths = access_control_paths(graph, [], lambda o: source_ref(o, root))
        return finding.id in {f.id for f in escalation_findings(graph, paths, root)}
    return any(
        f.detector == finding.detector and f.function == finding.function
        for f in build_findings(slither, results, root)
    )


def _slither_check(
    finding: Finding, sources: dict[str, str], workdir: Path, solc: str | None
) -> CheckResult:
    label = "AuditLens graph rule" if finding.origin == "auditlens-graph" else "Slither"
    name = f"{label} re-analysis: '{finding.detector}' on {finding.function}"
    root = workdir / "slither"
    root.mkdir(parents=True, exist_ok=True)
    for rel, code in sources.items():
        (root / Path(rel).name).write_text(code)
    target = root / Path(next(iter(sources))).name if len(sources) == 1 else root
    try:
        slither, results = run_slither(target, solc)
    except Exception as e:  # compilation errors surface as several exception types
        return CheckResult(name=name, status="error", detail=f"Slither failed: {e}")
    if _still_reported(finding, slither, results, root):
        return CheckResult(name=name, status="fail", detail="Still reported for this function.")
    return CheckResult(name=name, status="pass", detail="No longer reported for this function.")


def _verdict(
    compiled: bool,
    exploit: tuple[TestResult, TestResult],
    template: ExploitTemplate,
    legit: tuple[TestResult, TestResult] | None,
) -> tuple[PatchStatus, str]:
    """Baselines first, then decisive failures, then anything short of proof is inconclusive."""
    base_x, patch_x = exploit
    if not compiled:
        return PatchStatus.ERROR, "The patched project does not compile."
    if base_x.outcome != "passed":
        return PatchStatus.INCONCLUSIVE, (
            "The exploit test does not reproduce on the original "
            "source, so it cannot show the patch fixed anything."
        )
    if legit and legit[0].outcome != "passed":
        return PatchStatus.INCONCLUSIVE, (
            "The legitimate-use test fails on the original source; "
            "it is not a valid regression baseline."
        )
    if patch_x.outcome == "passed":
        return PatchStatus.FAILED, "The exploit still succeeds against the patched contract."
    if legit and legit[1].outcome != "passed":
        return PatchStatus.FAILED, (
            f"The patch breaks legitimate use: {legit[1].reason or legit[1].outcome}."
        )
    if patch_x.outcome != "property_held":
        return PatchStatus.INCONCLUSIVE, (
            "The exploit test failed on the patched contract for a "
            f"reason other than the security assertion "
            f"({patch_x.outcome})."
        )
    key = template.exercised_key
    if key and int(patch_x.observations.get(key, "0")) == 0:
        return PatchStatus.INCONCLUSIVE, (
            f"The exploit assertion failed but the attack path was never exercised ({key} = 0)."
        )
    if legit is None:
        return PatchStatus.INCONCLUSIVE, (
            "Exploit blocked, but no legitimate-use regression test is available for this finding."
        )
    return PatchStatus.VALIDATED, (
        "Exploit blocked on the patched contract with the attack path "
        "exercised, and legitimate use still passes."
    )


def _early_result(
    finding: Finding, proposal: PatchProposal, status: PatchStatus, summary: str
) -> PatchValidation:
    return PatchValidation(
        id=uuid.uuid4().hex[:12],
        finding_id=finding.id,
        patch_id=proposal.id,
        status=status,
        summary=summary,
        created_at=time.time(),
    )


def validate_patch(
    finding: Finding,
    sources: dict[str, str],
    proposal: PatchProposal,
    workdir: Path,
    solc: str | None,
) -> PatchValidation:
    exploit = build_template(finding, sources)
    if exploit is None or exploit.exercised_key is None:
        return _early_result(
            finding,
            proposal,
            PatchStatus.INCONCLUSIVE,
            "No exploit template with a measurable attack path applies to this "
            "finding, so the patch cannot be validated dynamically.",
        )
    available, reason = foundry_available()
    if not available:
        return _early_result(
            finding, proposal, PatchStatus.INCONCLUSIVE, f"Foundry sandbox unavailable ({reason})."
        )
    started = time.monotonic()
    legit = regression_template(finding, sources)
    tests = {exploit.test_file: exploit.source}
    if legit:
        tests[legit.test_file] = legit.source
    patched_sources = {**sources, proposal.file: proposal.patched_source}
    original_run = execute_suite(workdir / "original", sources, tests)
    patched_run = execute_suite(workdir / "patched", patched_sources, tests)
    checks = [
        CheckResult(
            name="Patched project compiles",
            status="pass" if patched_run.compiled else "error",
            detail="forge build succeeded"
            if patched_run.compiled
            else first_error(patched_run.build.text),
        )
    ]
    base_x, base_x_res = _test_check(
        "Exploit reproduces on original (baseline)", original_run, exploit, sources, "passed"
    )
    patch_x, patch_x_res = _test_check(
        "Exploit blocked on patched source", patched_run, exploit, patched_sources, "property_held"
    )
    checks += [base_x, patch_x]
    legit_results = None
    if legit:
        base_l, base_l_res = _test_check(
            "Legitimate use passes on original (baseline)", original_run, legit, sources, "passed"
        )
        patch_l, patch_l_res = _test_check(
            "Legitimate use passes on patched source", patched_run, legit, patched_sources, "passed"
        )
        checks += [base_l, patch_l]
        legit_results = (base_l_res, patch_l_res)
    status, summary = _verdict(
        patched_run.compiled, (base_x_res, patch_x_res), exploit, legit_results
    )
    if patched_run.compiled:
        checks.append(_slither_check(finding, patched_sources, workdir, solc))
    properties = [f"Exploit property: {exploit.asserted_property}"]
    if legit:
        properties.append(f"Regression property: {legit.asserted_property}")
    return PatchValidation(
        id=uuid.uuid4().hex[:12],
        finding_id=finding.id,
        patch_id=proposal.id,
        status=status,
        summary=summary,
        checks=checks,
        tested_properties=properties,
        limitations=[
            "Only the properties listed above were tested; this does not show the contract is "
            "secure against other attacks.",
            "The Slither re-analysis is reported for comparison and does not gate the verdict.",
            *exploit.limitations,
        ],
        created_at=time.time(),
        duration_s=round(time.monotonic() - started, 2),
    )

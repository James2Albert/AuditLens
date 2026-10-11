"""Deterministic regression benchmark for AuditLens.

Runs a fixed corpus (the bundled demo plus two patch fixtures) and compares each actual
outcome with the expected one. It measures only what it executes; it does not report
precision/recall, which would need a labelled dataset.

    python -m slither.tools.workbench.benchmark [--json] [--solc PATH]
"""

import argparse
import io
import json
import shutil
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from slither.tools.workbench.bundle import (
    build_bundle,
    bundle_recheck_inputs,
    recheck,
    verify_bundle,
)
from slither.tools.workbench.ledger import EvidenceLedger, record_scan
from slither.tools.workbench.models import Finding, Scan, ScanOptions, VerificationStatus
from slither.tools.workbench.scanner.orchestrator import Orchestrator, initial_stages
from slither.tools.workbench.verification.patch import propose_patch, user_patch, validate_patch
from slither.tools.workbench.verification.templates import ESCALATION_DETECTOR
from slither.tools.workbench.verification.runner import (
    ensure_foundry_on_path,
    foundry_available,
    forge_version,
    sandbox_available,
)

DEMO_DIR = Path(__file__).parent / "demo"
DEMO = DEMO_DIR / "VulnerableBank.sol"
FIXTURES = DEMO_DIR / "benchmark"


@dataclass
class CaseResult:
    case: str
    expected: str
    actual: str
    ok: bool
    seconds: float
    detail: str = ""


def _scan(options: ScanOptions, solc: str | None, workdir: Path) -> tuple[Scan, float]:
    scan = Scan(
        id="bench",
        name=DEMO.name,
        created_at=time.time(),
        options=options,
        stages=initial_stages(options),
    )
    started = time.monotonic()
    Orchestrator(scan, DEMO, solc, None, workdir, lambda _: None).run()
    return scan, round(time.monotonic() - started, 2)


def _reentrancy(scan: Scan) -> Finding | None:
    return next((f for f in scan.findings if f.detector == "reentrancy-eth"), None)


def _escalation(scan: Scan, privileged: str) -> Finding | None:
    return next(
        (
            f
            for f in scan.findings
            if f.detector == ESCALATION_DETECTOR
            and any(r.role == "privileged_function" and r.label == privileged for r in f.related)
        ),
        None,
    )


def _verified_case(name: str, finding: Finding | None) -> CaseResult:
    v = finding.verification if finding else None
    ok = v is not None and v.status is VerificationStatus.VERIFIED and bool(v.attack_exercised)
    return CaseResult(
        name,
        "verified_exploit, exercised",
        f"{v.status.value if v else 'missing'}, exercised={v.attack_exercised if v else None}",
        ok,
        v.duration_s if v else 0.0,
        "; ".join(f"{m.label}: {m.delta or m.after}" for m in (v.impact if v else [])),
    )


def scan_cases(solc: str | None, workdir: Path) -> tuple[list[CaseResult], Scan]:
    full, full_s = _scan(ScanOptions(), solc, workdir / "full")
    static, static_s = _scan(
        ScanOptions(ai_triage=False, attack_paths=False, dynamic_verification=False),
        solc,
        workdir / "static",
    )
    slither_detectors = sorted(f.detector for f in full.findings if f.origin == "slither")
    derived = len(full.findings) - len(slither_detectors)
    dynamic = sum(1 for f in full.findings if f.verification.run is not None)
    return [
        CaseResult(
            "scan completes (full pipeline)",
            "done",
            full.status,
            full.status == "done",
            full_s,
            f"{len(slither_detectors)} Slither findings ({', '.join(slither_detectors)}) "
            f"+ {derived} graph-rule findings",
        ),
        _verified_case("SC05 reentrancy-eth exploit reproduces on demo", _reentrancy(full)),
        _verified_case(
            "SC01 privilege escalation setOwner -> sweep reproduces",
            _escalation(full, "sweep()"),
        ),
        _verified_case(
            "SC01 privilege escalation setOwner -> payFee reproduces",
            _escalation(full, "payFee(uint256)"),
        ),
        CaseResult(
            "Slither-only baseline: same Slither findings, no execution evidence",
            f"{len(slither_detectors)} findings, 0 executed",
            f"{len(static.findings)} findings, 0 executed",
            sorted(f.detector for f in static.findings) == slither_detectors,
            static_s,
            f"full pipeline adds {derived} graph-rule findings and executed tests for "
            f"{dynamic} finding(s)",
        ),
    ], full


def _patch_case(
    name: str,
    expected: str,
    finding: Finding,
    scan: Scan,
    make: Callable,
    solc: str | None,
    workdir: Path,
) -> CaseResult:
    started = time.monotonic()
    proposal = make()
    if proposal is None:
        return CaseResult(name, expected, "no patch", False, 0.0)
    result = validate_patch(finding, scan.sources, proposal, workdir, solc)
    checks = "; ".join(f"{c.name}: {c.status}" for c in result.checks)
    return CaseResult(
        name,
        expected,
        result.status.value,
        result.status.value == expected,
        round(time.monotonic() - started, 2),
        checks,
    )


def reentrancy_patch_cases(scan: Scan, solc: str | None, workdir: Path) -> list[CaseResult]:
    finding = _reentrancy(scan)
    if finding is None:
        return [CaseResult("reentrancy patch cases", "finding", "missing", False, 0.0)]
    file = finding.location.file
    broken = scan.sources[file].replace("balances[msg.sender] = 0;", "balances[msg.sender] = 0")
    cases = [
        ("generated CEI patch is validated", "validated", "generated"),
        ("hand-written fix (negative control) is validated", "validated", "fixed.sol"),
        ("fix that disables withdraw() fails regression", "failed", "withdraw_disabled.sol"),
        ("patch with a syntax error is an error, not a fix", "error", broken),
    ]
    return [
        _patch_case(
            f"SC05 {name}",
            expected,
            finding,
            scan,
            _maker(finding, scan, file, source),
            solc,
            workdir / f"re{i}",
        )
        for i, (name, expected, source) in enumerate(cases)
    ]


def escalation_patch_cases(scan: Scan, solc: str | None, workdir: Path) -> list[CaseResult]:
    finding = _escalation(scan, "sweep()")
    if finding is None:
        return [CaseResult("escalation patch cases", "finding", "missing", False, 0.0)]
    file = finding.location.file
    frozen = scan.sources[file].replace("owner = newOwner;", 'revert("ownership frozen");')
    cases = [
        ("generated access-check patch is validated", "validated", "generated"),
        ("hand-written fix (negative control) is validated", "validated", "fixed.sol"),
        ("patch leaving setOwner unguarded fails", "failed", "withdraw_disabled.sol"),
        ("patch that freezes ownership fails regression", "failed", frozen),
    ]
    return [
        _patch_case(
            f"SC01 {name}",
            expected,
            finding,
            scan,
            _maker(finding, scan, file, source),
            solc,
            workdir / f"ac{i}",
        )
        for i, (name, expected, source) in enumerate(cases)
    ]


def _tamper(bundle: bytes) -> bytes:
    """Change one source line inside the bundle, keeping the manifest as it was."""
    source, target = io.BytesIO(bundle), io.BytesIO()
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(target, "w") as new:
        for info in old.infolist():
            data = old.read(info)
            if info.filename == "sources/original/VulnerableBank.sol":
                data = data.replace(b"require(amount > 0", b"require(amount >= 0")
            new.writestr(info, data)
    return target.getvalue()


def bundle_cases(scan: Scan, workdir: Path) -> list[CaseResult]:
    workdir.mkdir(parents=True, exist_ok=True)
    ledger = EvidenceLedger(workdir / "ledger.db")
    record_scan(ledger, scan)
    data, manifest = build_bundle(scan, ledger)
    claims, tests = bundle_recheck_inputs(data)
    verified = verify_bundle(data, workdir / "verify")
    cases = [
        CaseResult(
            "proof bundle re-executes and reproduces",
            "reproduced",
            verified.verdict,
            verified.verdict == "reproduced",
            verified.duration_s,
            f"{len(manifest['claims'])} claims; {verified.summary}",
        )
    ]
    tampered = verify_bundle(_tamper(data), workdir / "tampered")
    cases.append(
        CaseResult(
            "tampered bundle is detected",
            "tampered",
            tampered.verdict,
            tampered.verdict == "tampered",
            tampered.duration_s,
            "; ".join(tampered.integrity_problems[:2]),
        )
    )
    for name, expected, source in (
        (
            "recheck: hand-written fix blocks every proven exploit",
            "all_blocked",
            (FIXTURES / "fixed.sol").read_text(),
        ),
        ("recheck: original code is flagged as a regression", "regression", DEMO.read_text()),
    ):
        result = recheck(claims, tests, {DEMO.name: source}, workdir / expected)
        cases.append(
            CaseResult(
                name,
                expected,
                result.verdict,
                result.verdict == expected,
                result.duration_s,
                result.summary,
            )
        )
    return cases


def _maker(finding: Finding, scan: Scan, file: str, source: str) -> Callable:
    """'generated' -> template patch, a fixture name -> that file, else literal source."""
    if source == "generated":
        return lambda: propose_patch(finding, scan.sources)[0]
    if source.endswith(".sol"):
        return lambda: user_patch(finding, scan.sources, file, (FIXTURES / source).read_text())
    return lambda: user_patch(finding, scan.sources, file, source)


def run(solc: str | None) -> dict:
    ensure_foundry_on_path()
    available, reason = foundry_available()
    with tempfile.TemporaryDirectory(prefix="auditlens-bench-") as tmp:
        workdir = Path(tmp)
        cases, scan = scan_cases(solc, workdir)
        if available:
            cases += reentrancy_patch_cases(scan, solc, workdir / "patches")
            cases += escalation_patch_cases(scan, solc, workdir / "patches")
            cases += bundle_cases(scan, workdir / "bundle")
    return {
        "environment": {
            "foundry": available,
            "foundry_detail": reason if not available else "",
            "forge_version": forge_version(),
            "sandboxed": sandbox_available(),
            "solc": solc,
        },
        "cases": [asdict(c) for c in cases],
        "passed": sum(1 for c in cases if c.ok),
        "failed": sum(1 for c in cases if not c.ok),
    }


def _print_table(report: dict) -> None:
    env = report["environment"]
    print(
        f"forge: {env['forge_version'] or 'unavailable'} | sandboxed: {env['sandboxed']} | "
        f"solc: {env['solc']}"
    )
    for case in report["cases"]:
        mark = "PASS" if case["ok"] else "FAIL"
        print(
            f"[{mark}] {case['case']}  (expected {case['expected']}; got {case['actual']}; "
            f"{case['seconds']}s)"
        )
        if case["detail"]:
            print(f"       {case['detail']}")
    print(f"\n{report['passed']} passed, {report['failed']} failed")


def main() -> None:
    parser = argparse.ArgumentParser(description="AuditLens deterministic benchmark")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--solc", default=None, help="Path to the solc binary")
    args = parser.parse_args()
    report = run(args.solc or shutil.which("solc"))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_table(report)
    sys.exit(1 if report["failed"] else 0)


if __name__ == "__main__":
    main()

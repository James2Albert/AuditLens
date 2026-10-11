"""Attack paths only gain dynamic status from a test of their own category."""

from slither.tools.workbench.graph.finding_paths import annotate_with_evidence
from slither.tools.workbench.models import ExecutionRun, VerificationStatus
from slither.tools.workbench.verification.impact import measure


def _run() -> ExecutionRun:
    return ExecutionRun(
        run_id="r1",
        test_file="t",
        test_contract="c",
        test_function="f",
        test_sha256="x",
        source_sha256="y",
    )


def test_paths_start_as_static_hypotheses(static_scan):
    assert {p.evidence_status for p in static_scan.attack_paths} == {"static-hypothesis"}


def test_verified_exercised_run_demonstrates_only_matching_path(static_scan):
    scan = static_scan.model_copy(deep=True)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    finding.verification.status = VerificationStatus.VERIFIED
    finding.verification.attack_exercised = True
    finding.verification.run = _run()
    annotate_with_evidence(scan.attack_paths, scan.findings)
    by_category = {p.category: p for p in scan.attack_paths}
    assert by_category["reentrancy"].evidence_status == "dynamically-demonstrated"
    assert by_category["reentrancy"].run_ids == ["r1"]
    assert by_category["access-control"].evidence_status == "static-hypothesis"


def test_verified_without_exercised_attack_is_not_demonstrated(static_scan):
    scan = static_scan.model_copy(deep=True)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    finding.verification.status = VerificationStatus.VERIFIED
    finding.verification.attack_exercised = None
    finding.verification.run = _run()
    annotate_with_evidence(scan.attack_paths, scan.findings)
    assert (
        next(p for p in scan.attack_paths if p.category == "reentrancy").evidence_status
        == "inconclusive"
    )


def test_impact_omits_measurements_without_values():
    assert measure("reentrancy", {}) == []
    partial = measure("reentrancy", {"contract_balance_before": "5", "contract_balance_after": "x"})
    assert partial == []
    held = measure(
        "reentrancy",
        {"victim_deposit_wei": str(5 * 10**18), "contract_balance_after": str(5 * 10**18)},
    )
    assert held[0].violated is False

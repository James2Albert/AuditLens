"""Security score: one deduction per root cause, verification raises weight once."""

from slither.tools.workbench.models import Finding, VerificationStatus
from slither.tools.workbench.reports.builder import build_summary, score_breakdown


def _finding(fid, impact, detector="d", category=None, function="f()", verified=False):
    finding = Finding(
        id=fid,
        detector=detector,
        title=f"t-{fid}",
        impact=impact,
        confidence="High",
        description="",
        category=category,
        function=function,
    )
    if verified:
        finding.verification.status = VerificationStatus.VERIFIED
    return finding


def test_same_class_same_function_counts_once():
    findings = [
        _finding(
            "a", "High", category="access-control", function="setOwner(address)", verified=True
        ),
        _finding(
            "b", "High", category="access-control", function="setOwner(address)", verified=True
        ),
    ]
    [deduction] = score_breakdown(findings)
    assert deduction.points == 30
    assert deduction.finding_ids == ["a", "b"]


def test_verification_raises_weight_instead_of_adding():
    assert score_breakdown([_finding("a", "High")])[0].points == 20
    assert score_breakdown([_finding("a", "High", verified=True)])[0].points == 30


def test_worst_finding_in_root_cause_sets_weight():
    findings = [
        _finding("a", "Low", detector="reentrancy-events", category="reentrancy"),
        _finding("b", "High", detector="reentrancy-eth", category="reentrancy"),
    ]
    [deduction] = score_breakdown(findings)
    assert (deduction.points, deduction.impact) == (20, "High")


def test_different_functions_or_classes_are_separate():
    findings = [
        _finding("a", "Medium", category="unchecked-call", function="payFee(uint256)"),
        _finding("b", "Low", detector="missing-zero-check", function="setOwner(address)"),
        _finding("c", "Low", detector="missing-zero-check", function="other(address)"),
    ]
    assert sorted(d.points for d in score_breakdown(findings)) == [3, 3, 8]


def test_informational_and_optimization_are_free():
    findings = [_finding("a", "Informational", function=None), _finding("b", "Optimization")]
    assert score_breakdown(findings) == []


def test_demo_score_is_explainable(static_scan):
    scan = static_scan.model_copy(deep=True)
    for f in scan.findings:
        if f.detector in ("reentrancy-eth", "auditlens-privilege-escalation"):
            f.verification.status = VerificationStatus.VERIFIED
    summary = build_summary(scan)
    assert summary.security_score == 29
    assert summary.security_score == 100 - sum(d.points for d in summary.score_breakdown)
    causes = {d.root_cause: d.points for d in summary.score_breakdown}
    assert causes == {
        "access-control in setOwner(address)": 30,
        "reentrancy in withdraw()": 30,
        "unchecked-call in payFee(uint256)": 8,
        "missing-zero-check in setOwner(address)": 3,
    }

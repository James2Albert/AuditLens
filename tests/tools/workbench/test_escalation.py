"""SC01 privilege escalation: graph-derived findings, differential exploit, guard patch."""

import pytest

from slither.tools.workbench.models import PatchStatus, VerificationStatus
from slither.tools.workbench.verification.patch import propose_patch, user_patch, validate_patch
from slither.tools.workbench.verification.runner import verify
from slither.tools.workbench.verification.templates import (
    ESCALATION_DETECTOR,
    build_template,
    regression_template,
)
from tests.tools.workbench.conftest import FIXTURES, SOLC, needs_foundry


def _escalation(scan, privileged):
    return next(
        f.model_copy(deep=True)
        for f in scan.findings
        if f.detector == ESCALATION_DETECTOR
        and any(r.role == "privileged_function" and r.label == privileged for r in f.related)
    )


def test_graph_rule_derives_one_finding_per_escalation_path(static_scan):
    derived = [f for f in static_scan.findings if f.detector == ESCALATION_DETECTOR]
    assert {f.origin for f in derived} == {"auditlens-graph"}
    assert {f.function for f in derived} == {"setOwner(address)"}
    privileged = {r.label for f in derived for r in f.related if r.role == "privileged_function"}
    assert privileged == {"payFee(uint256)", "sweep()"}
    for finding in derived:
        paths = [p for p in static_scan.attack_paths if finding.id in p.finding_ids]
        assert [p.category for p in paths] == ["access-control"]
        assert "not the output of a Slither detector" in finding.description


def test_slither_findings_are_unchanged(static_scan):
    slither = sorted(f.detector for f in static_scan.findings if f.origin == "slither")
    assert ESCALATION_DETECTOR not in slither
    assert "reentrancy-eth" in slither


def test_templates_are_differential(static_scan):
    finding = _escalation(static_scan, "sweep()")
    exploit = build_template(finding, static_scan.sources)
    assert exploit.exercised_key == "escalation_attempted"
    assert exploit.source.count('abi.encodeWithSignature("sweep()")') == 2
    assert 'abi.encodeWithSignature("setOwner(address)", attacker)' in exploit.source
    legit = regression_template(finding, static_scan.sources)
    assert 'abi.encodeWithSignature("setOwner(address)", newOwner)' in legit.source


def test_no_template_when_constructor_needs_arguments(static_scan):
    finding = _escalation(static_scan, "sweep()")
    sources = {
        k: v.replace("constructor()", "constructor(uint256 x)")
        for k, v in static_scan.sources.items()
    }
    assert build_template(finding, sources) is None


def test_guard_patch_inserts_check_into_writer(static_scan):
    finding = _escalation(static_scan, "sweep()")
    proposal, reason = propose_patch(finding, static_scan.sources)
    assert reason == ""
    assert proposal.strategy == "add-access-check"
    assert '+        require(msg.sender == owner, "caller is not owner");' in proposal.diff


def test_guard_patch_refused_for_non_address_guard(static_scan):
    finding = _escalation(static_scan, "sweep()")
    sources = {
        k: v.replace("address public owner;", "mapping(address => bool) public owner;")
        for k, v in static_scan.sources.items()
    }
    proposal, reason = propose_patch(finding, sources)
    assert proposal is None
    assert "plain address" in reason


@needs_foundry
@pytest.mark.parametrize(
    "privileged, contract_delta", [("sweep()", "-5 ETH"), ("payFee(uint256)", "-1 wei")]
)
def test_escalation_exploit_verified_with_measured_impact(
    static_scan, tmp_path, privileged, contract_delta
):
    finding = _escalation(static_scan, privileged)
    v = verify(finding, static_scan.sources, tmp_path)
    assert v.status is VerificationStatus.VERIFIED, v.summary
    assert v.attack_exercised is True
    impact = {m.key: m for m in v.impact}
    assert impact["privileged_access"].before == "reverted"
    assert impact["privileged_access"].after == "succeeded"
    assert impact["privileged_access"].violated is True
    assert impact["contract_balance"].delta == contract_delta


@needs_foundry
def test_directly_unprotected_function_is_not_called_escalation(static_scan, tmp_path):
    finding = _escalation(static_scan, "sweep()")
    sources = {
        k: v.replace(
            '    function sweep() external {\n        require(msg.sender == owner, "not owner");',
            "    function sweep() external {",
        )
        for k, v in static_scan.sources.items()
    }
    v = verify(finding, sources, tmp_path)
    assert v.status is VerificationStatus.INCONCLUSIVE
    assert v.run.outcome == "undetermined"


@needs_foundry
@pytest.mark.parametrize(
    "patch, expected",
    [
        ("generated", PatchStatus.VALIDATED),
        ("fixed.sol", PatchStatus.VALIDATED),
        ("withdraw_disabled.sol", PatchStatus.FAILED),
        ("frozen", PatchStatus.FAILED),
    ],
)
def test_escalation_patch_validation(static_scan, tmp_path, patch, expected):
    finding = _escalation(static_scan, "sweep()")
    sources = static_scan.sources
    if patch == "generated":
        proposal = propose_patch(finding, sources)[0]
    elif patch == "frozen":
        frozen = sources["VulnerableBank.sol"].replace(
            "owner = newOwner;", 'revert("ownership frozen");'
        )
        proposal = user_patch(finding, sources, "VulnerableBank.sol", frozen)
    else:
        proposal = user_patch(
            finding, sources, "VulnerableBank.sol", (FIXTURES / patch).read_text()
        )
    result = validate_patch(finding, sources, proposal, tmp_path, SOLC)
    assert result.status is expected, result.summary
    static = next(c for c in result.checks if "graph rule re-analysis" in c.name)
    assert static.status == ("fail" if patch == "withdraw_disabled.sol" else "pass")

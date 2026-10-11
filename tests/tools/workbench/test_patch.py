"""Patch generation and validation."""

import pytest

from slither.tools.workbench.models import PatchStatus
from slither.tools.workbench.verification.patch import propose_patch, user_patch, validate_patch
from tests.tools.workbench.conftest import FIXTURES, SOLC, needs_foundry


def test_generated_patch_moves_write_before_call(reentrancy, static_scan):
    proposal, reason = propose_patch(reentrancy, static_scan.sources)
    assert reason == ""
    assert proposal.origin == "generated-template"
    lines = proposal.patched_source.splitlines()
    write = lines.index("        balances[msg.sender] = 0;")
    call = next(i for i, l in enumerate(lines) if "msg.sender.call" in l)
    assert write < call
    assert "+        balances[msg.sender] = 0;" in proposal.diff
    assert static_scan.sources["VulnerableBank.sol"] != proposal.patched_source


def test_no_generated_patch_for_other_detectors(static_scan):
    unchecked = next(f for f in static_scan.findings if f.detector == "unchecked-lowlevel")
    proposal, reason = propose_patch(unchecked, static_scan.sources)
    assert proposal is None
    assert "reentrancy-eth" in reason


def test_refuses_to_move_write_that_depends_on_call_result(reentrancy, static_scan):
    sources = {
        "VulnerableBank.sol": static_scan.sources["VulnerableBank.sol"].replace(
            "balances[msg.sender] = 0;", "balances[msg.sender] = ok ? 0 : amount;"
        )
    }
    proposal, reason = propose_patch(reentrancy, sources)
    assert proposal is None
    assert "after the external call" in reason


def test_user_patch_input_validation(reentrancy, static_scan):
    original = static_scan.sources["VulnerableBank.sol"]
    with pytest.raises(ValueError, match="not a source file"):
        user_patch(reentrancy, static_scan.sources, "../../etc/passwd", "x")
    with pytest.raises(ValueError, match="identical"):
        user_patch(reentrancy, static_scan.sources, "VulnerableBank.sol", original)


@needs_foundry
@pytest.mark.parametrize(
    "fixture, expected",
    [
        ("generated", PatchStatus.VALIDATED),
        ("fixed.sol", PatchStatus.VALIDATED),
        ("withdraw_disabled.sol", PatchStatus.FAILED),
        ("syntax", PatchStatus.ERROR),
    ],
)
def test_patch_validation_outcomes(reentrancy, static_scan, tmp_path, fixture, expected):
    sources = static_scan.sources
    if fixture == "generated":
        proposal = propose_patch(reentrancy, sources)[0]
    elif fixture == "syntax":
        broken = sources["VulnerableBank.sol"].replace(
            "balances[msg.sender] = 0;", "balances[msg.sender] = 0"
        )
        proposal = user_patch(reentrancy, sources, "VulnerableBank.sol", broken)
    else:
        proposal = user_patch(
            reentrancy, sources, "VulnerableBank.sol", (FIXTURES / fixture).read_text()
        )
    result = validate_patch(reentrancy, sources, proposal, tmp_path, SOLC)
    assert result.status is expected, result.summary
    checks = {c.name: c for c in result.checks}
    assert checks["Exploit reproduces on original (baseline)"].status == "pass"
    if expected is PatchStatus.VALIDATED:
        blocked = checks["Exploit blocked on patched source"]
        assert blocked.status == "pass"
        assert (
            blocked.run.test_sha256
            == checks["Exploit reproduces on original (baseline)"].run.test_sha256
        )
        assert checks["Legitimate use passes on patched source"].status == "pass"


@needs_foundry
def test_patch_that_still_allows_exploit_fails(reentrancy, static_scan, tmp_path):
    cosmetic = static_scan.sources["VulnerableBank.sol"].replace(
        "// Do not deploy.", "// Reviewed."
    )
    proposal = user_patch(reentrancy, static_scan.sources, "VulnerableBank.sol", cosmetic)
    result = validate_patch(reentrancy, static_scan.sources, proposal, tmp_path, SOLC)
    assert result.status is PatchStatus.FAILED
    assert "still succeeds" in result.summary

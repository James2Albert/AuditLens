"""Verification runner: outcome classification, provenance and sandbox guarantees."""

import json

import pytest

from slither.tools.workbench.models import VerificationStatus
from slither.tools.workbench.verification import runner
from slither.tools.workbench.verification.runner import (
    TestResult,
    classify,
    execute_suite,
    parse_test_json,
    sha256_text,
    sources_digest,
    verify,
)
from slither.tools.workbench.verification.templates import (
    NOT_REPRODUCED_MARKER,
    build_template,
)
from tests.tools.workbench.conftest import needs_foundry

SUITE = "test/Exploit.t.sol:ReentrancyTest"


def _forge_json(status: str, reason: str | None, logs: list[str]) -> str:
    return json.dumps(
        {
            SUITE: {
                "test_results": {
                    "testReentrancy()": {
                        "status": status,
                        "reason": reason,
                        "decoded_logs": logs,
                    }
                }
            }
        }
    )


def test_parse_success_with_observations():
    results = parse_test_json(_forge_json("Success", None, ["reentry_attempts: 5"]))
    result = results[f"{SUITE}::testReentrancy"]
    assert result.outcome == "passed"
    assert result.observations == {"reentry_attempts": "5"}


@pytest.mark.parametrize(
    "reason, outcome",
    [
        (f"{NOT_REPRODUCED_MARKER}: attacker did not extract more ETH", "property_held"),
        ("setup failed: revert: no balance", "setup_failed"),
        ("revert: transfer failed", "reverted"),
        (None, "reverted"),
    ],
)
def test_parse_failure_reasons(reason, outcome):
    results = parse_test_json(_forge_json("Failure", reason, []))
    assert results[f"{SUITE}::testReentrancy"].outcome == outcome


def test_parse_garbage_returns_nothing():
    assert parse_test_json("Error: compiler run failed") == {}
    assert parse_test_json("{not json") == {}


@pytest.mark.parametrize(
    "outcome, status",
    [
        ("passed", VerificationStatus.VERIFIED),
        ("property_held", VerificationStatus.NOT_VERIFIED),
        ("reverted", VerificationStatus.INCONCLUSIVE),
        ("undetermined", VerificationStatus.INCONCLUSIVE),
        ("setup_failed", VerificationStatus.ERROR),
        ("compile_error", VerificationStatus.ERROR),
        ("timeout", VerificationStatus.ERROR),
        ("infra_error", VerificationStatus.ERROR),
        ("missing", VerificationStatus.ERROR),
    ],
)
def test_classification_never_treats_failures_as_evidence(reentrancy, static_scan, outcome, status):
    template = build_template(reentrancy, static_scan.sources)
    observations = {"reentry_attempts": "1"}
    assert classify(TestResult(outcome, None, observations), template)[0] is status


def test_property_held_without_exercising_attack_is_inconclusive(reentrancy, static_scan):
    template = build_template(reentrancy, static_scan.sources)
    result = TestResult("property_held", NOT_REPRODUCED_MARKER, {"reentry_attempts": "0"})
    status, summary, exercised = classify(result, template)
    assert status is VerificationStatus.INCONCLUSIVE
    assert exercised is False
    assert "never exercised" in summary


def test_sources_digest_is_order_independent():
    assert sources_digest({"a.sol": "1", "b.sol": "2"}) == sources_digest(
        {"b.sol": "2", "a.sol": "1"}
    )
    assert sources_digest({"a.sol": "1"}) != sources_digest({"a.sol": "2"})


@needs_foundry
def test_verify_links_run_to_exact_test(reentrancy, static_scan, tmp_path):
    v = verify(reentrancy, static_scan.sources, tmp_path)
    assert v.status is VerificationStatus.VERIFIED
    assert v.attack_exercised is True
    assert v.run.test_sha256 == sha256_text(v.test_source)
    assert v.run.source_sha256 == sources_digest(static_scan.sources)
    assert v.run.outcome == "passed"
    assert (v.run.test_contract, v.run.test_function) == ("ReentrancyTest", "testReentrancy")
    assert "VulnerableBank::withdraw" in v.trace
    solvency = next(m for m in v.impact if m.key == "solvency_invariant")
    assert solvency.violated is True


@needs_foundry
def test_compile_failure_is_error_not_verdict(reentrancy, static_scan, tmp_path):
    broken = {k: v + "\nthis is not solidity\n" for k, v in static_scan.sources.items()}
    v = verify(reentrancy, broken, tmp_path)
    assert v.status is VerificationStatus.ERROR
    assert v.run.outcome == "compile_error"
    assert v.impact == []


@needs_foundry
def test_timeout_is_error(reentrancy, static_scan, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "EXECUTION_TIMEOUT_S", 0.001)
    v = verify(reentrancy, static_scan.sources, tmp_path)
    assert v.status is VerificationStatus.ERROR
    assert v.run.outcome == "timeout"


TEST_HEADER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
"""


@needs_foundry
def test_setup_failure_and_unrelated_revert(tmp_path):
    source = (
        TEST_HEADER
        + """
contract BrokenSetup is Test {
    function setUp() public { revert("fixture broken"); }
    function testX() public {}
}
contract Unrelated is Test {
    function testY() public { revert("unrelated"); }
}
"""
    )
    suite = execute_suite(tmp_path, {}, {"test/Probe.t.sol": source})
    assert suite.result("test/Probe.t.sol", "BrokenSetup", "testX").outcome == "setup_failed"
    assert suite.result("test/Probe.t.sol", "Unrelated", "testY").outcome == "reverted"
    assert suite.result("test/Probe.t.sol", "Unrelated", "testMissing").outcome == "missing"


@needs_foundry
def test_sandbox_hides_server_environment_and_blocks_ffi(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITLENS_TEST_SECRET", "leaked")
    source = (
        TEST_HEADER
        + """
contract Isolation is Test {
    function testEnvCleared() public {
        assertEq(vm.envOr("AUDITLENS_TEST_SECRET", string("absent")), "absent");
    }
    function testFfiDisabled() public {
        string[] memory cmd = new string[](1);
        cmd[0] = "true";
        vm.ffi(cmd);
    }
    function testFsReadDenied() public {
        vm.readFile("/etc/hostname");
    }
}
"""
    )
    suite = execute_suite(tmp_path, {}, {"test/Iso.t.sol": source})
    assert suite.result("test/Iso.t.sol", "Isolation", "testEnvCleared").outcome == "passed"
    assert suite.result("test/Iso.t.sol", "Isolation", "testFfiDisabled").outcome == "reverted"
    assert suite.result("test/Iso.t.sol", "Isolation", "testFsReadDenied").outcome == "reverted"

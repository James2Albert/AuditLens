"""End-to-end and unit tests for the Slither Security Workbench."""

import shutil
import time
from pathlib import Path

import pytest

from slither.tools.workbench.ai.heuristic import heuristic_assess
from slither.tools.workbench.ai.triage import parse_assessment
from slither.tools.workbench.models import (
    Exploitability,
    Scan,
    ScanOptions,
    VerificationStatus,
)
from slither.tools.workbench.reports.builder import build_markdown_report, build_summary
from slither.tools.workbench.scanner.orchestrator import Orchestrator, initial_stages

DEMO = Path(__file__).parents[3] / "slither" / "tools" / "workbench" / "demo" / "VulnerableBank.sol"
SOLC = shutil.which("solc")


def _run_scan(tmp_path, options=None) -> Scan:
    opts = options or ScanOptions()
    scan = Scan(id="test", name="demo", created_at=time.time(), options=opts,
                stages=initial_stages(opts))
    Orchestrator(scan, DEMO, SOLC, None, tmp_path, lambda s: None).run()
    return scan


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_static_analysis_finds_reentrancy(tmp_path):
    scan = _run_scan(tmp_path)
    assert scan.status == "done"
    detectors = {f.detector for f in scan.findings}
    assert "reentrancy-eth" in detectors
    assert "unchecked-lowlevel" in detectors


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_evidence_extracted_for_reentrancy(tmp_path):
    scan = _run_scan(tmp_path)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    assert finding.evidence is not None
    assert finding.evidence.sends_eth is True
    assert "balances" in finding.evidence.state_written
    assert finding.category == "reentrancy"


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_heuristic_triage_runs_without_provider(tmp_path):
    scan = _run_scan(tmp_path)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    assert finding.assessment is not None
    assert finding.assessment.provider == "heuristic"
    assert finding.assessment.classification == Exploitability.LIKELY


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_attack_paths_generated(tmp_path):
    scan = _run_scan(tmp_path)
    categories = {p.category for p in scan.attack_paths}
    assert "reentrancy" in categories
    assert "access-control" in categories
    reentrancy = next(p for p in scan.attack_paths if p.category == "reentrancy")
    assert any(n.kind == "attacker-controlled" for n in reentrancy.nodes)
    assert reentrancy.narrative


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_access_control_path_links_writer_and_sink(tmp_path):
    scan = _run_scan(tmp_path)
    ac = next(p for p in scan.attack_paths if p.category == "access-control")
    labels = [n.label for n in ac.nodes]
    assert "owner" in labels
    assert any("selfdestruct" in l.lower() or "eth transfer" in l.lower() for l in labels)


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_verification_inconclusive_without_foundry(tmp_path):
    scan = _run_scan(tmp_path)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    if shutil.which("forge") is None:
        assert finding.verification.status is VerificationStatus.INCONCLUSIVE
        assert finding.verification.test_source
        assert "ReentrancyTest" in finding.verification.test_source


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
@pytest.mark.skipif(shutil.which("forge") is None, reason="foundry not installed")
def test_verification_reproduces_reentrancy_with_foundry(tmp_path):
    scan = _run_scan(tmp_path)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    v = finding.verification
    assert v.status is VerificationStatus.VERIFIED
    assert int(v.observations["attacker_gained_wei"]) > int(v.observations["attacker_deposit_wei"])
    assert v.observations["contract_balance_after"] == "0"


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_summary_and_report(tmp_path):
    scan = _run_scan(tmp_path)
    summary = build_summary(scan)
    assert summary.total_findings == len(scan.findings)
    assert summary.high >= 1
    assert 0 <= summary.security_score <= 100
    report = build_markdown_report(scan)
    assert "Executive Summary" in report
    assert "reentrancy" in report.lower()


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_disabled_stages_are_skipped(tmp_path):
    opts = ScanOptions(ai_triage=False, attack_paths=False, dynamic_verification=False)
    scan = _run_scan(tmp_path, opts)
    assert scan.status == "done"
    assert scan.findings
    assert not scan.attack_paths
    assert all(f.assessment is None for f in scan.findings)


def test_parse_assessment_valid():
    text = '{"classification": "likely_exploitable", "confidence": 90, "summary": "x"}'
    assessment = parse_assessment(text)
    assert assessment.classification == Exploitability.LIKELY
    assert assessment.confidence == 90


def test_parse_assessment_clamps_and_defaults():
    text = '{"classification": "nonsense", "confidence": 250}'
    assessment = parse_assessment(text)
    assert assessment.classification == Exploitability.UNKNOWN
    assert assessment.confidence == 100


def test_parse_assessment_rejects_garbage():
    with pytest.raises(ValueError):
        parse_assessment("the model refused to answer")


def test_parse_assessment_extracts_embedded_json():
    text = 'Here is my answer:\n{"classification": "unknown", "confidence": 10}\nThanks!'
    assessment = parse_assessment(text)
    assert assessment.confidence == 10

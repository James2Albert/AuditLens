"""Security Evidence Ledger: persistence, hash chain, evidence assembly."""

import sqlite3

from slither.tools.workbench.ledger import (
    EvidenceKind,
    EvidenceLedger,
    evidence_record,
    record_scan,
)
from slither.tools.workbench.models import ExecutionRun, VerificationStatus


def test_chain_verifies_and_detects_tampering(tmp_path):
    ledger = EvidenceLedger(tmp_path / "l.db")
    for i in range(3):
        ledger.append("scan", EvidenceKind.STATIC, f"f{i}", {"n": i})
    status = ledger.verify_chain("scan")
    assert status.valid and status.entries == 3
    with sqlite3.connect(tmp_path / "l.db") as conn:
        conn.execute("UPDATE entries SET payload = ? WHERE seq = 2", ('{"n":99}',))
    broken = ledger.verify_chain("scan")
    assert not broken.valid
    assert broken.broken_at == 2


def test_chains_are_per_scan(tmp_path):
    ledger = EvidenceLedger(tmp_path / "l.db")
    a = ledger.append("a", EvidenceKind.STATIC, None, {})
    b = ledger.append("b", EvidenceKind.STATIC, None, {})
    assert a.prev_hash == b.prev_hash == "0" * 64


def test_scan_persists_across_instances(static_scan, tmp_path):
    EvidenceLedger(tmp_path / "l.db").save_scan(static_scan)
    loaded = EvidenceLedger(tmp_path / "l.db").load_scans()
    assert [s.id for s in loaded] == [static_scan.id]
    assert loaded[0].findings == static_scan.findings


def test_evidence_record_keeps_categories_separate(static_scan, tmp_path):
    scan = static_scan.model_copy(deep=True)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    finding.verification.status = VerificationStatus.INCONCLUSIVE
    finding.verification.summary = "Foundry unavailable"
    ledger = EvidenceLedger(tmp_path / "l.db")
    record_scan(ledger, scan)
    record = evidence_record(ledger, scan, finding)
    assert record["static_fact"]["payload"]["detector"] == "reentrancy-eth"
    assert record["static_fact"]["payload"]["file_sha256"]
    assert record["ai_hypothesis"]["payload"]["category"] == "ai_hypothesis"
    assert record["executions"][0]["payload"]["status"] == "inconclusive"
    assert record["remediations"] == []
    assert [e["payload"]["path_id"] for e in record["attack_paths"]] == ["re-1"]
    assert record["chain"]["valid"]


def test_unrecorded_run_is_flagged(static_scan, tmp_path):
    scan = static_scan.model_copy(deep=True)
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    ledger = EvidenceLedger(tmp_path / "l.db")
    record_scan(ledger, scan)
    finding.verification.run = ExecutionRun(
        run_id="notinledger",
        test_file="t",
        test_contract="c",
        test_function="f",
        test_sha256="x",
        source_sha256="y",
    )
    assert evidence_record(ledger, scan, finding)["current_run_recorded"] is False

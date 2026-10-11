"""Proof-carrying bundles, re-verification, tamper detection and exploit regression checks."""

import hashlib
import io
import json
import subprocess
import sys
import zipfile

import pytest

from slither.tools.workbench.bundle import (
    MAX_BUNDLE_BYTES,
    build_bundle,
    bundle_recheck_inputs,
    recheck,
    verify_bundle,
)
from slither.tools.workbench.ledger import EvidenceKind, EvidenceLedger, record_scan
from slither.tools.workbench.models import ScanOptions
from slither.tools.workbench.reports.builder import hypothesis_scorecard
from slither.tools.workbench.verification.patch import propose_patch, validate_patch
from tests.tools.workbench.conftest import DEMO, FIXTURES, FOUNDRY, SOLC, run_demo

pytestmark = pytest.mark.skipif(not FOUNDRY or SOLC is None, reason="foundry or solc missing")


@pytest.fixture(scope="module")
def proof(tmp_path_factory):
    """A verified demo scan with a validated reentrancy patch, its ledger and its bundle."""
    root = tmp_path_factory.mktemp("proof")
    scan = run_demo(root / "scan", ScanOptions())
    finding = next(f for f in scan.findings if f.detector == "reentrancy-eth")
    finding.patch = propose_patch(finding, scan.sources)[0]
    finding.remediation = validate_patch(finding, scan.sources, finding.patch, root / "p", SOLC)
    ledger = EvidenceLedger(root / "ledger.db")
    record_scan(ledger, scan)
    ledger.append(
        scan.id,
        EvidenceKind.REMEDIATION,
        finding.id,
        {"category": "remediation", **finding.remediation.model_dump()},
    )
    data, manifest = build_bundle(scan, ledger)
    return scan, data, manifest


def _rewrite(data: bytes, edit) -> bytes:
    """Copy the bundle, letting `edit(name, bytes, manifest)` change members."""
    src = zipfile.ZipFile(io.BytesIO(data))
    manifest = json.loads(src.read("manifest.json"))
    members = {i.filename: src.read(i) for i in src.infolist() if i.filename != "manifest.json"}
    edit(members, manifest)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, body in members.items():
            archive.writestr(name, body)
    return out.getvalue()


def test_bundle_contains_exploit_and_patch_claims(proof):
    _, _, manifest = proof
    ids = [c["id"].split(":")[0] for c in manifest["claims"]]
    assert ids.count("exploit") == 3  # reentrancy + two escalation paths
    assert ids.count("patch") == 4
    assert all(c["ledger_entry"] for c in manifest["claims"])
    assert {"ledger.json", "report.md"} <= set(manifest["files"])


def test_bundle_reproduces(proof, tmp_path):
    _, data, manifest = proof
    result = verify_bundle(data, tmp_path)
    assert result.verdict == "reproduced", result.integrity_problems
    assert len(result.claims) == len(manifest["claims"])
    assert all(c.reproduced for c in result.claims)


def test_modified_source_is_tampered(proof, tmp_path):
    def edit(members, _):
        path = "sources/original/VulnerableBank.sol"
        members[path] = members[path].replace(b"amount > 0", b"amount >= 0")

    result = verify_bundle(_rewrite(proof[1], edit), tmp_path)
    assert result.verdict == "tampered"
    assert "hash mismatch: sources/original/VulnerableBank.sol" in result.integrity_problems
    assert result.claims == []


def test_rehashed_source_still_caught_by_claim_digest(proof, tmp_path):
    def edit(members, manifest):
        path = "sources/original/VulnerableBank.sol"
        members[path] = members[path].replace(b"amount > 0", b"amount >= 0")
        manifest["files"][path] = hashlib.sha256(members[path]).hexdigest()

    result = verify_bundle(_rewrite(proof[1], edit), tmp_path)
    assert result.verdict == "tampered"
    assert any(
        "sources do not match the recorded source digest" in p for p in result.integrity_problems
    )


def test_edited_ledger_breaks_chain(proof, tmp_path):
    def edit(members, manifest):
        ledger = json.loads(members["ledger.json"])
        ledger["entries"][1]["payload"]["impact"] = "Low"
        members["ledger.json"] = json.dumps(ledger).encode()
        manifest["files"]["ledger.json"] = hashlib.sha256(members["ledger.json"]).hexdigest()

    result = verify_bundle(_rewrite(proof[1], edit), tmp_path)
    assert result.verdict == "tampered"
    assert not result.ledger["valid"]


def test_changed_claim_outcome_is_a_mismatch(proof, tmp_path):
    def edit(_, manifest):
        manifest["claims"][0]["expected_outcome"] = "property_held"

    result = verify_bundle(_rewrite(proof[1], edit), tmp_path)
    assert result.verdict == "mismatch"
    assert not result.claims[0].reproduced


def test_unsafe_and_unlisted_members_rejected(proof, tmp_path):
    def edit(members, _):
        members["../evil.sh"] = b"rm -rf /"
        members["extra.txt"] = b"x"

    result = verify_bundle(_rewrite(proof[1], edit), tmp_path)
    assert result.verdict == "tampered"
    assert "unsafe path: ../evil.sh" in result.integrity_problems
    assert "unlisted file: extra.txt" in result.integrity_problems
    assert not (tmp_path.parent / "evil.sh").exists()


def test_invalid_and_oversized_bundles_raise(tmp_path):
    with pytest.raises(ValueError, match="Not a valid bundle"):
        verify_bundle(b"not a zip", tmp_path)
    with pytest.raises(ValueError, match="exceeds"):
        verify_bundle(b"0" * (MAX_BUNDLE_BYTES + 1), tmp_path)


@pytest.mark.parametrize(
    "version, expected, exploitable",
    [
        ("fixed.sol", "all_blocked", 0),
        ("withdraw_disabled.sol", "regression", 2),
        ("original", "regression", 3),
    ],
)
def test_recheck(proof, tmp_path, version, expected, exploitable):
    claims, tests = bundle_recheck_inputs(proof[1])
    source = DEMO.read_text() if version == "original" else (FIXTURES / version).read_text()
    result = recheck(claims, tests, {"VulnerableBank.sol": source}, tmp_path)
    assert result.verdict == expected
    assert sum(r.verdict == "exploitable" for r in result.results) == exploitable


def test_recheck_renamed_contract_is_inconclusive_not_safe(proof, tmp_path):
    claims, tests = bundle_recheck_inputs(proof[1])
    renamed = (
        (FIXTURES / "fixed.sol").read_text().replace("contract VulnerableBank", "contract Bank")
    )
    result = recheck(claims, tests, {"VulnerableBank.sol": renamed}, tmp_path)
    assert result.verdict == "inconclusive"
    assert {r.verdict for r in result.results} == {"inconclusive"}


def test_scorecard_grades_only_decided_runs(proof):
    card = hypothesis_scorecard(proof[0].findings)
    assert card["confirmed"] == 3
    assert card["refuted"] == card["missed"] == 0
    assert card["untested"] >= 1  # e.g. the unchecked-call hypothesis has no exploit run


def test_cli_exit_codes(proof, tmp_path):
    bundle = tmp_path / "proof.zip"
    bundle.write_bytes(proof[1])
    cli = [sys.executable, "-m", "slither.tools.workbench"]
    ok = subprocess.run(
        [*cli, "verify-bundle", str(bundle), "--json"], capture_output=True, text=True, check=False
    )
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["verdict"] == "reproduced"
    regression = subprocess.run(
        [*cli, "recheck", str(bundle), str(DEMO)], capture_output=True, text=True, check=False
    )
    assert regression.returncode == 1
    assert "REGRESSION" in regression.stdout

"""API-level tests for the workbench using FastAPI's TestClient."""

import shutil
import time

import pytest
from fastapi.testclient import TestClient

from slither.tools.workbench.api.app import create_app
from tests.tools.workbench.conftest import DEMO, FOUNDRY

DEMO_DIR = DEMO.parent

SOLC = shutil.which("solc")


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(solc=SOLC, data_dir=tmp_path))


def test_status_endpoint(client):
    data = client.get("/api/status").json()
    assert "ai_provider" in data
    assert data["has_demo"] is True


def test_rejects_unsupported_file(client):
    files = [("files", ("evil.exe", b"nope", "application/octet-stream"))]
    response = client.post("/api/scans", files=files)
    assert response.status_code == 400


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_demo_scan_completes(client):
    scan_id = client.post("/api/scans/demo").json()["id"]
    for _ in range(120):
        data = client.get(f"/api/scans/{scan_id}").json()
        if data["status"] in ("done", "failed"):
            break
        time.sleep(0.5)
    assert data["status"] == "done"
    assert data["summary"]["total_findings"] >= 1
    assert client.get(f"/api/scans/{scan_id}/report.md").status_code == 200
    assert client.get(f"/api/scans/{scan_id}/report.json").status_code == 200


def test_missing_scan_returns_404(client):
    assert client.get("/api/scans/deadbeef").status_code == 404


def _wait(client, scan_id):
    for _ in range(240):
        data = client.get(f"/api/scans/{scan_id}").json()
        if data["status"] in ("done", "failed"):
            return data
        time.sleep(0.25)
    raise AssertionError("scan did not finish")


def test_invalid_options_rejected(client):
    response = client.post("/api/scans/demo?options=notjson")
    assert response.status_code == 400
    assert "Invalid scan options" in response.json()["detail"]


def test_unknown_finding_and_scan(client):
    assert client.post("/api/scans/0123456789ab/findings/abc/verify").status_code == 404
    assert client.delete("/api/scans/0123456789ab").status_code == 404


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_recheck_requires_verified_exploit(client):
    opts = '{"dynamic_verification": false}'
    sid = _wait(client, client.post(f"/api/scans/demo?options={opts}").json()["id"])["id"]
    files = [("files", ("VulnerableBank.sol", b"contract A {}", "text/plain"))]
    assert client.post(f"/api/scans/{sid}/recheck", files=files).status_code == 409


@pytest.mark.skipif(SOLC is None, reason="solc not installed")
def test_patch_endpoints_validate_input(client):
    opts = '{"dynamic_verification": false}'
    data = _wait(client, client.post(f"/api/scans/demo?options={opts}").json()["id"])
    sid = data["id"]
    finding = next(f for f in data["findings"] if f["detector"] == "reentrancy-eth")
    other = next(f for f in data["findings"] if f["detector"] == "unchecked-lowlevel")
    base = f"/api/scans/{sid}/findings"
    assert client.post(f"{base}/{finding['id']}/patch/validate").status_code == 409
    assert client.post(f"{base}/{other['id']}/patch").status_code == 400
    bad = client.post(f"{base}/{finding['id']}/patch", json={"file": "../x.sol", "source": "x"})
    assert bad.status_code == 400
    assert client.get(f"{base}/{finding['id']}/test.sol").status_code == 404


@pytest.mark.skipif(SOLC is None or not FOUNDRY, reason="solc or foundry missing")
def test_full_evidence_workflow_survives_restart(tmp_path):
    client = TestClient(create_app(solc=SOLC, data_dir=tmp_path))
    data = _wait(client, client.post("/api/scans/demo").json()["id"])
    sid = data["id"]
    finding = next(f for f in data["findings"] if f["detector"] == "reentrancy-eth")
    fid = finding["id"]
    assert finding["verification"]["status"] == "verified_exploit"
    base = f"/api/scans/{sid}/findings/{fid}"

    evidence = client.get(f"{base}/evidence").json()
    assert evidence["static_fact"] and evidence["ai_hypothesis"] and evidence["executions"]
    assert evidence["current_run_recorded"]

    run_id = client.post(f"{base}/verify").json()["verification"]["run"]["run_id"]
    patch = client.post(f"{base}/patch").json()["patch"]
    validation = client.post(f"{base}/patch/validate").json()
    assert validation["status"] == "validated"
    assert "pragma solidity" in client.get(f"{base}/test.sol").text

    report = client.get(f"/api/scans/{sid}/report.md").text
    for expected in (
        "Evidence Classification",
        run_id,
        patch["id"],
        validation["id"],
        "Evidence Ledger",
        "not a production estimate",
    ):
        assert expected in report
    assert "/scans/" not in report  # no server paths leak into Slither descriptions
    exported = client.get(f"/api/scans/{sid}/report.json").json()
    assert exported["report_version"] == 2
    assert exported["evidence_ledger"]["chain"]["valid"]

    bundle = client.get(f"/api/scans/{sid}/bundle.zip")
    assert bundle.status_code == 200
    assert bundle.headers["content-type"] == "application/zip"
    verdict = client.post(
        "/api/bundles/verify", files={"bundle": ("b.zip", bundle.content, "application/zip")}
    ).json()
    assert verdict["verdict"] == "reproduced"
    fixed = (DEMO_DIR / "benchmark" / "fixed.sol").read_bytes()
    rechecked = client.post(
        f"/api/scans/{sid}/recheck", files=[("files", ("VulnerableBank.sol", fixed, "text/plain"))]
    ).json()
    assert rechecked["verdict"] == "all_blocked"
    bad = client.post(f"/api/scans/{sid}/recheck", files=[("files", ("x.exe", b"x", "text/plain"))])
    assert bad.status_code == 400
    assert (
        client.post("/api/bundles/verify", files={"bundle": ("b.zip", b"nope", "x")}).status_code
        == 400
    )
    assert data["summary"]["ai_scorecard"]["confirmed"] >= 1

    restarted = TestClient(create_app(solc=SOLC, data_dir=tmp_path))
    reloaded = restarted.get(f"/api/scans/{sid}").json()
    again = next(f for f in reloaded["findings"] if f["id"] == fid)
    assert again["verification"]["run"]["run_id"] == run_id
    assert again["remediation"]["status"] == "validated"
    path = next(p for p in reloaded["attack_paths"] if p["category"] == "reentrancy")
    assert path["evidence_status"] == "dynamically-demonstrated"
    assert path["patch_status"] == "validated"
    kinds = {e["kind"] for e in restarted.get(f"/api/scans/{sid}/ledger").json()["entries"]}
    assert {
        "static_fact",
        "ai_hypothesis",
        "execution",
        "remediation",
        "attack_path",
        "regression_check",
    } <= kinds

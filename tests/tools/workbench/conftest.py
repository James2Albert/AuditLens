"""Shared fixtures for the AuditLens workbench tests."""

import shutil
import time
from pathlib import Path

import pytest

from slither.tools.workbench.models import Finding, Scan, ScanOptions
from slither.tools.workbench.scanner.orchestrator import Orchestrator, initial_stages
from slither.tools.workbench.verification.runner import ensure_foundry_on_path, foundry_available

ensure_foundry_on_path()

DEMO = Path(__file__).parents[3] / "slither" / "tools" / "workbench" / "demo" / "VulnerableBank.sol"
FIXTURES = DEMO.parent / "benchmark"
SOLC = shutil.which("solc")
FOUNDRY = foundry_available()[0]

needs_solc = pytest.mark.skipif(SOLC is None, reason="solc not installed")
needs_foundry = pytest.mark.skipif(
    not FOUNDRY or SOLC is None,
    reason="foundry (with vendored forge-std + solc cache) or solc missing",
)


def run_demo(workdir: Path, options: ScanOptions) -> Scan:
    scan = Scan(
        id="0123456789ab",
        name="demo",
        created_at=time.time(),
        options=options,
        stages=initial_stages(options),
    )
    Orchestrator(scan, DEMO, SOLC, None, workdir, lambda _: None).run()
    return scan


@pytest.fixture(scope="session")
def static_scan(tmp_path_factory) -> Scan:
    """Demo scan with static analysis, heuristic triage and attack paths (no execution)."""
    if SOLC is None:
        pytest.skip("solc not installed")
    return run_demo(tmp_path_factory.mktemp("static"), ScanOptions(dynamic_verification=False))


@pytest.fixture
def reentrancy(static_scan) -> Finding:
    return next(f for f in static_scan.findings if f.detector == "reentrancy-eth").model_copy(
        deep=True
    )

"""Scan store with background execution, SQLite persistence and the evidence ledger.

Scans are kept in memory for fast polling and written through to SQLite on every update,
so they survive restarts. Artifacts (uploaded sources, Foundry workspaces) live under the
data directory, outside the package tree. User sources are never modified: patches are
only applied inside throwaway validation workspaces.
"""

import os
import shutil
import threading
import time
import uuid
from pathlib import Path

from slither.tools.workbench.ai.provider import config_from_env, make_provider
from slither.tools.workbench.bundle import (
    Recheck,
    BundleVerification,
    build_bundle,
    recheck,
    scan_recheck_inputs,
    verify_bundle,
)
from slither.tools.workbench.graph.finding_paths import annotate_with_evidence
from slither.tools.workbench.ledger import (
    EvidenceKind,
    EvidenceLedger,
    evidence_record,
    execution_payload,
    path_payload,
    proposal_payload,
    record_scan,
    validation_payload,
)
from slither.tools.workbench.models import Finding, PatchValidation, Scan, ScanOptions
from slither.tools.workbench.scanner.orchestrator import Orchestrator, initial_stages
from slither.tools.workbench.verification.patch import propose_patch, user_patch, validate_patch
from slither.tools.workbench.verification.runner import verify

VALID_SUFFIXES = {".sol", ".vy"}
MAX_UPLOAD_BYTES = 2_000_000
INTERRUPTED = "Interrupted: the server stopped before this scan finished. Start a new scan."


def default_data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "auditlens"


class NotFound(LookupError):
    pass


class Conflict(RuntimeError):
    pass


class ScanStore:
    def __init__(self, artifact_root: Path | None = None, solc: str | None = None) -> None:
        self._lock = threading.Lock()
        self._busy: set[str] = set()
        self.artifact_root = artifact_root or default_data_dir()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.solc = solc
        self.ledger = EvidenceLedger(self.artifact_root / "auditlens.db")
        self._scans: dict[str, Scan] = {}
        for scan in self.ledger.load_scans():
            if scan.status in ("queued", "running"):
                scan.status, scan.error = "failed", INTERRUPTED
                self.ledger.save_scan(scan)
            self._scans[scan.id] = scan

    def list_scans(self) -> list[Scan]:
        with self._lock:
            return sorted(self._scans.values(), key=lambda s: s.created_at, reverse=True)

    def get(self, scan_id: str) -> Scan | None:
        with self._lock:
            return self._scans.get(scan_id)

    def _save(self, scan: Scan) -> None:
        with self._lock:
            self._scans[scan.id] = scan
        self.ledger.save_scan(scan)

    def create_scan(self, name: str, files: dict[str, bytes], options: ScanOptions) -> Scan:
        scan_id = uuid.uuid4().hex[:12]
        target = self._write_sources(scan_id, files)
        scan = Scan(
            id=scan_id,
            name=name,
            created_at=time.time(),
            options=options,
            stages=initial_stages(options),
        )
        self._save(scan)
        thread = threading.Thread(target=self._run, args=(scan, target), daemon=True)
        thread.start()
        return scan

    def _write_sources(self, scan_id: str, files: dict[str, bytes]) -> Path:
        prepared = []
        for name, content in files.items():
            safe = Path(name or "").name
            if Path(safe).suffix not in VALID_SUFFIXES:
                raise ValueError(f"Unsupported file type: '{safe}'. Upload .sol or .vy files.")
            if len(content) > MAX_UPLOAD_BYTES:
                raise ValueError(f"{safe} exceeds the {MAX_UPLOAD_BYTES}-byte size limit")
            prepared.append((safe, content))
        if not prepared:
            raise ValueError("No valid contract files provided")
        source_dir = self.artifact_root / "scans" / scan_id / "src"
        source_dir.mkdir(parents=True, exist_ok=True)
        written = []
        for safe, content in prepared:
            path = source_dir / safe
            path.write_bytes(content)
            written.append(path)
        return written[0] if len(written) == 1 else source_dir

    def _workdir(self, scan_id: str, *parts: str) -> Path:
        path = self.artifact_root.joinpath("scans", scan_id, *parts)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _run(self, scan: Scan, target: Path) -> None:
        provider = None
        try:
            provider = make_provider(config_from_env())
        except Exception:
            provider = None
        try:
            Orchestrator(
                scan, target, self.solc, provider, self._workdir(scan.id, "verify"), self._save
            ).run()
        except Exception as e:
            scan.status, scan.error = "failed", f"Unexpected pipeline error: {e}"
            self._save(scan)
            raise
        finally:
            record_scan(self.ledger, scan)

    def delete(self, scan_id: str) -> None:
        with self._lock:
            self._scans.pop(scan_id, None)
        self.ledger.delete_scan(scan_id)
        shutil.rmtree(self.artifact_root / "scans" / scan_id, ignore_errors=True)

    def _finding(self, scan_id: str, finding_id: str) -> tuple[Scan, Finding]:
        scan = self.get(scan_id)
        if scan is None:
            raise NotFound("Scan not found")
        finding = next((f for f in scan.findings if f.id == finding_id), None)
        if finding is None:
            raise NotFound(f"Finding {finding_id} not found in scan {scan_id}")
        return scan, finding

    def _exclusive(self, scan: Scan, finding: Finding) -> str:
        if scan.status != "done":
            raise Conflict(f"Scan is '{scan.status}'; wait for it to finish.")
        key = f"{scan.id}:{finding.id}"
        with self._lock:
            if key in self._busy:
                raise Conflict("Another verification or validation is running for this finding.")
            self._busy.add(key)
        return key

    def _release(self, key: str) -> None:
        with self._lock:
            self._busy.discard(key)

    def evidence(self, scan_id: str, finding_id: str) -> dict:
        scan, finding = self._finding(scan_id, finding_id)
        return evidence_record(self.ledger, scan, finding)

    def bundle(self, scan_id: str) -> tuple[bytes, dict]:
        scan = self.get(scan_id)
        if scan is None:
            raise NotFound("Scan not found")
        if scan.status != "done":
            raise Conflict(f"Scan is '{scan.status}'; wait for it to finish.")
        return build_bundle(scan, self.ledger)

    def verify_bundle(self, data: bytes) -> BundleVerification:
        workdir = self.artifact_root / "bundles" / uuid.uuid4().hex[:12]
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            return verify_bundle(data, workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def recheck(self, scan_id: str, files: dict[str, bytes]) -> Recheck:
        scan = self.get(scan_id)
        if scan is None:
            raise NotFound("Scan not found")
        if scan.status != "done":
            raise Conflict(f"Scan is '{scan.status}'; wait for it to finish.")
        sources = {}
        for name, content in files.items():
            safe = Path(name or "").name
            if Path(safe).suffix != ".sol":
                raise ValueError(f"Unsupported file type: '{safe}'. Upload .sol files.")
            if len(content) > MAX_UPLOAD_BYTES:
                raise ValueError(f"{safe} exceeds the {MAX_UPLOAD_BYTES}-byte size limit")
            try:
                sources[safe] = content.decode()
            except UnicodeDecodeError as e:
                raise ValueError(f"{safe} is not UTF-8 text") from e
        if not sources:
            raise ValueError("No contract files provided")
        claims, tests = scan_recheck_inputs(scan)
        if not any(c.id.startswith("exploit:") and c.expected_outcome == "passed" for c in claims):
            raise Conflict("This scan has no verified exploits to recheck.")
        workdir = self._workdir(scan.id, "recheck", uuid.uuid4().hex[:12])
        result = recheck(claims, tests, sources, workdir)
        self.ledger.append(
            scan.id,
            EvidenceKind.REGRESSION,
            None,
            {"category": "regression_check", "files": sorted(sources), **result.model_dump()},
        )
        return result

    def _record_paths(self, scan: Scan, finding: Finding) -> None:
        annotate_with_evidence(scan.attack_paths, scan.findings)
        for path in scan.attack_paths:
            if finding.id in path.finding_ids and path.run_ids:
                self.ledger.append(scan.id, EvidenceKind.ATTACK_PATH, None, path_payload(path))

    def verify_finding(self, scan_id: str, finding_id: str) -> Finding:
        scan, finding = self._finding(scan_id, finding_id)
        key = self._exclusive(scan, finding)
        try:
            finding.verification = verify(
                finding, scan.sources, self._workdir(scan.id, "verify", finding.id)
            )
            self.ledger.append(
                scan.id, EvidenceKind.EXECUTION, finding.id, execution_payload(finding, scan)
            )
            self._record_paths(scan, finding)
            self._save(scan)
        finally:
            self._release(key)
        return finding

    def propose_patch(
        self, scan_id: str, finding_id: str, file: str | None = None, source: str | None = None
    ) -> Finding:
        scan, finding = self._finding(scan_id, finding_id)
        if scan.status != "done":
            raise Conflict(f"Scan is '{scan.status}'; wait for it to finish.")
        if source is not None:
            proposal = user_patch(
                finding,
                scan.sources,
                file or (finding.location.file if finding.location else ""),
                source,
            )
        else:
            proposal, reason = propose_patch(finding, scan.sources)
            if proposal is None:
                raise ValueError(reason)
        finding.patch = proposal
        finding.remediation = None
        self.ledger.append(
            scan.id, EvidenceKind.REMEDIATION, finding.id, proposal_payload(proposal)
        )
        self._save(scan)
        return finding

    def validate_patch(self, scan_id: str, finding_id: str) -> PatchValidation:
        scan, finding = self._finding(scan_id, finding_id)
        if finding.patch is None:
            raise Conflict("No patch proposed for this finding; generate or supply one first.")
        key = self._exclusive(scan, finding)
        try:
            proposal = finding.patch
            workdir = self._workdir(scan.id, "patches", finding.id, uuid.uuid4().hex[:12])
            validation = validate_patch(finding, scan.sources, proposal, workdir, self.solc)
            finding.remediation = validation
            self.ledger.append(
                scan.id,
                EvidenceKind.REMEDIATION,
                finding.id,
                validation_payload(validation, proposal),
            )
            self._record_paths(scan, finding)
            self._save(scan)
        finally:
            self._release(key)
        return validation

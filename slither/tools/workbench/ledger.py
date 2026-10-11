"""Security Evidence Ledger: persistent, hash-chained evidence records in local SQLite.

What the hashes provide:
  * Each entry stores the SHA-256 of its canonical JSON payload and a hash chaining it to
    the previous entry of the same scan. `verify_chain` recomputes both, so accidental
    corruption or an edit that does not recompute every later hash is detected.
  * Reports embed entry hashes and the chain head, so a report can be checked against
    the ledger it was generated from.

What they do NOT provide: anyone who can write the database file can rewrite the whole
chain consistently. A hash shows two artifacts are identical, not that either is true.
"""

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from slither.tools.workbench.models import (
    AttackPath,
    Finding,
    PatchProposal,
    PatchValidation,
    Scan,
    VerificationStatus,
)
from slither.tools.workbench.verification.runner import sha256_text, sources_digest

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, created_at REAL NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT UNIQUE NOT NULL,
    scan_id TEXT NOT NULL,
    finding_id TEXT,
    kind TEXT NOT NULL,
    created_at REAL NOT NULL,
    payload TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_scan ON entries (scan_id, seq);
"""


class EvidenceKind(str, Enum):
    STATIC = "static_fact"
    AI = "ai_hypothesis"
    EXECUTION = "execution"
    REMEDIATION = "remediation"
    ATTACK_PATH = "attack_path"
    SCAN_EVENT = "scan_event"
    REGRESSION = "regression_check"


class LedgerEntry(BaseModel):
    seq: int
    id: str
    scan_id: str
    finding_id: str | None
    kind: EvidenceKind
    created_at: float
    payload: dict
    payload_sha256: str
    prev_hash: str
    entry_hash: str


class ChainStatus(BaseModel):
    valid: bool
    entries: int
    head: str
    broken_at: int | None = None
    guarantee: str = (
        "Detects corruption or edits that do not rewrite every later hash. "
        "Does not prevent a full rewrite by someone with write access to the "
        "database file."
    )


def verify_entries(entries: list[dict]) -> ChainStatus:
    """Recompute the chain over stored rows (payload as a string) or exported entries (dict)."""
    prev = GENESIS
    for entry in entries:
        payload = entry["payload"]
        body = payload if isinstance(payload, str) else canonical(payload)
        payload_sha = hashlib.sha256(body.encode()).hexdigest()
        expected = _entry_hash(
            prev,
            entry["id"],
            entry["scan_id"],
            entry["finding_id"],
            entry["kind"],
            entry["created_at"],
            payload_sha,
        )
        if (
            payload_sha != entry["payload_sha256"]
            or entry["prev_hash"] != prev
            or expected != entry["entry_hash"]
        ):
            return ChainStatus(valid=False, entries=len(entries), head=prev, broken_at=entry["seq"])
        prev = entry["entry_hash"]
    return ChainStatus(valid=True, entries=len(entries), head=prev)


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(
    prev: str,
    entry_id: str,
    scan_id: str,
    finding_id: str | None,
    kind: str,
    created_at: float,
    payload_sha256: str,
) -> str:
    header = canonical(
        {
            "prev": prev,
            "id": entry_id,
            "scan_id": scan_id,
            "finding_id": finding_id,
            "kind": kind,
            "created_at": repr(created_at),
            "payload_sha256": payload_sha256,
        }
    )
    return hashlib.sha256(header.encode()).hexdigest()


class EvidenceLedger:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def save_scan(self, scan: Scan) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (id, created_at, data) VALUES (?, ?, ?)",
                (scan.id, scan.created_at, scan.model_dump_json()),
            )

    def load_scans(self) -> list[Scan]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT data FROM scans ORDER BY created_at").fetchall()
        return [Scan.model_validate_json(row["data"]) for row in rows]

    def delete_scan(self, scan_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.execute("DELETE FROM entries WHERE scan_id = ?", (scan_id,))

    def append(
        self, scan_id: str, kind: EvidenceKind, finding_id: str | None, payload: dict
    ) -> LedgerEntry:
        entry_id = uuid.uuid4().hex[:16]
        created_at = time.time()
        body = canonical(payload)
        payload_sha = hashlib.sha256(body.encode()).hexdigest()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT entry_hash FROM entries WHERE scan_id = ? ORDER BY seq DESC LIMIT 1",
                (scan_id,),
            ).fetchone()
            prev = row["entry_hash"] if row else GENESIS
            entry_hash = _entry_hash(
                prev, entry_id, scan_id, finding_id, kind.value, created_at, payload_sha
            )
            cursor = conn.execute(
                "INSERT INTO entries (id, scan_id, finding_id, kind, created_at, payload, "
                "payload_sha256, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry_id,
                    scan_id,
                    finding_id,
                    kind.value,
                    created_at,
                    body,
                    payload_sha,
                    prev,
                    entry_hash,
                ),
            )
            seq = cursor.lastrowid
        return LedgerEntry(
            seq=seq,
            id=entry_id,
            scan_id=scan_id,
            finding_id=finding_id,
            kind=kind,
            created_at=created_at,
            payload=payload,
            payload_sha256=payload_sha,
            prev_hash=prev,
            entry_hash=entry_hash,
        )

    def entries(self, scan_id: str, finding_id: str | None = None) -> list[LedgerEntry]:
        query = "SELECT * FROM entries WHERE scan_id = ?"
        args: tuple = (scan_id,)
        if finding_id is not None:
            query += " AND finding_id = ?"
            args += (finding_id,)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query + " ORDER BY seq", args).fetchall()
        return [LedgerEntry(**{**dict(row), "payload": json.loads(row["payload"])}) for row in rows]

    def verify_chain(self, scan_id: str) -> ChainStatus:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM entries WHERE scan_id = ? ORDER BY seq", (scan_id,)
            ).fetchall()
        return verify_entries([dict(row) for row in rows])


def static_payload(finding: Finding, scan: Scan) -> dict:
    file = finding.location.file if finding.location else None
    return {
        "category": "static_fact",
        "detector": finding.detector,
        "origin": finding.origin,
        "title": finding.title,
        "impact": finding.impact,
        "confidence": finding.confidence,
        "description": finding.description,
        "contract": finding.contract,
        "function": finding.function,
        "location": finding.location.model_dump() if finding.location else None,
        "related": [r.model_dump() for r in finding.related],
        "function_evidence": finding.evidence.model_dump(exclude={"code"})
        if finding.evidence
        else None,
        "file_sha256": sha256_text(scan.sources[file]) if file in scan.sources else None,
        "sources_sha256": sources_digest(scan.sources),
        "compiler": scan.compiler,
    }


def ai_payload(finding: Finding) -> dict:
    a = finding.assessment
    return {
        "category": "ai_hypothesis",
        "provider": a.provider,
        "model": a.model,
        "classification": a.classification.value,
        "confidence": a.confidence,
        "summary": a.summary,
        "assumptions": a.preconditions,
        "attack_steps": a.attack_steps,
        "remediation": a.remediation,
        "raw_error": a.raw_error,
    }


def execution_payload(finding: Finding, scan: Scan) -> dict:
    v = finding.verification
    return {
        "category": "execution",
        "status": v.status.value,
        "summary": v.summary,
        "template": v.template,
        "test_sha256": sha256_text(v.test_source) if v.test_source else None,
        "sources_sha256": sources_digest(scan.sources),
        "run": v.run.model_dump() if v.run else None,
        "attack_exercised": v.attack_exercised,
        "observations": v.observations,
        "impact": [m.model_dump() for m in v.impact],
        "limitations": v.limitations,
    }


def path_payload(path: AttackPath) -> dict:
    return {
        "category": "attack_path",
        "path_id": path.id,
        "path_category": path.category,
        "title": path.title,
        "finding_ids": path.finding_ids,
        "derived_from": path.derived_from,
        "evidence_status": path.evidence_status,
        "run_ids": path.run_ids,
        "nodes": [n.id for n in path.nodes],
        "edges": [list(e) for e in path.edges],
    }


def proposal_payload(proposal: PatchProposal) -> dict:
    return {
        "category": "remediation",
        "stage": "proposed",
        **proposal.model_dump(exclude={"patched_source"}),
    }


def validation_payload(validation: PatchValidation, proposal: PatchProposal) -> dict:
    return {
        "category": "remediation",
        "stage": "validated",
        "patch_sha256": proposal.patched_sha256,
        "patch_origin": proposal.origin,
        **validation.model_dump(),
    }


def record_scan(ledger: EvidenceLedger, scan: Scan) -> None:
    """Record every piece of evidence a finished (or failed) scan produced."""
    ledger.append(
        scan.id,
        EvidenceKind.SCAN_EVENT,
        None,
        {
            "category": "scan_event",
            "status": scan.status,
            "error": scan.error,
            "name": scan.name,
            "sources_sha256": sources_digest(scan.sources),
            "stages": [s.model_dump() for s in scan.stages],
        },
    )
    for finding in scan.findings:
        ledger.append(scan.id, EvidenceKind.STATIC, finding.id, static_payload(finding, scan))
        if finding.assessment:
            ledger.append(scan.id, EvidenceKind.AI, finding.id, ai_payload(finding))
        if finding.verification.status is not VerificationStatus.NOT_RUN:
            ledger.append(
                scan.id, EvidenceKind.EXECUTION, finding.id, execution_payload(finding, scan)
            )
    for path in scan.attack_paths:
        ledger.append(scan.id, EvidenceKind.ATTACK_PATH, None, path_payload(path))


def evidence_record(ledger: EvidenceLedger, scan: Scan, finding: Finding) -> dict:
    """Assemble the four evidence categories for one finding, kept separate."""
    own = ledger.entries(scan.id, finding.id)
    paths = [
        e
        for e in ledger.entries(scan.id)
        if e.kind is EvidenceKind.ATTACK_PATH and finding.id in e.payload["finding_ids"]
    ]
    by_kind = {kind: [e.model_dump() for e in own if e.kind is kind] for kind in EvidenceKind}
    executions = by_kind[EvidenceKind.EXECUTION]
    current_run = finding.verification.run
    return {
        "scan_id": scan.id,
        "project": scan.name,
        "finding_id": finding.id,
        "detector": finding.detector,
        "location": finding.location.model_dump() if finding.location else None,
        "static_fact": by_kind[EvidenceKind.STATIC][-1] if by_kind[EvidenceKind.STATIC] else None,
        "ai_hypothesis": by_kind[EvidenceKind.AI][-1] if by_kind[EvidenceKind.AI] else None,
        "attack_paths": [e.model_dump() for e in paths],
        "executions": executions,
        "remediations": by_kind[EvidenceKind.REMEDIATION],
        "current_run_recorded": current_run is None
        or any(
            (e["payload"].get("run") or {}).get("run_id") == current_run.run_id for e in executions
        ),
        "chain": ledger.verify_chain(scan.id).model_dump(),
    }

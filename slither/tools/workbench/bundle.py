"""Proof-carrying audit bundles, bundle re-verification and exploit regression checks.

A bundle is a zip holding everything needed to re-execute every dynamic claim a scan makes:
the original (and patched) sources, the exact generated tests, the evidence ledger and the
Markdown report. `manifest.json` lists each file's SHA-256 and each claim:

    "test T, run against source set S, produced outcome O (run R, ledger entry E)"

`verify_bundle` checks file hashes and the ledger chain, then re-runs every claim in the
sandbox and compares outcomes. `recheck` runs the proven exploits against a new version of
the code, so a fixed vulnerability that comes back is caught.

Guarantees: a reproduced bundle shows that these tests, on these sources, still behave as
recorded on the verifier's machine. It does not show that the tests are the right tests.
"""

import hashlib
import io
import json
import time
import zipfile
from pathlib import Path, PurePosixPath

from pydantic import BaseModel

from slither.tools.workbench.ledger import EvidenceLedger, verify_entries
from slither.tools.workbench.models import Finding, Scan
from slither.tools.workbench.reports.builder import build_markdown_report
from slither.tools.workbench.verification.runner import (
    execute_suite,
    foundry_available,
    forge_version,
    sandbox_available,
    sha256_text,
    sources_digest,
)
from slither.tools.workbench.verification.templates import build_template, regression_template

BUNDLE_VERSION = 1
MAX_BUNDLE_BYTES = 20_000_000
MAX_UNCOMPRESSED_BYTES = 60_000_000
MAX_MEMBERS = 400
MAX_SOURCE_BYTES = 2_000_000


class Claim(BaseModel):
    id: str
    finding_id: str
    title: str
    description: str
    variant: str
    test_path: str
    test_file: str
    test_contract: str
    test_function: str
    test_sha256: str
    sources_sha256: str
    expected_outcome: str
    exercised_key: str | None = None
    run_id: str
    ledger_entry: str | None = None


class ClaimResult(BaseModel):
    claim_id: str
    description: str
    expected: str
    actual: str
    reproduced: bool
    detail: str = ""


class BundleVerification(BaseModel):
    verdict: str
    summary: str
    bundle_sha256: str
    scan_name: str = ""
    integrity_problems: list[str] = []
    ledger: dict = {}
    claims: list[ClaimResult] = []
    environment: dict = {}
    duration_s: float = 0.0


class RecheckResult(BaseModel):
    claim_id: str
    finding_id: str
    title: str
    verdict: str
    outcome: str
    detail: str = ""


class Recheck(BaseModel):
    verdict: str
    summary: str
    new_sources_sha256: str
    results: list[RecheckResult] = []
    duration_s: float = 0.0


def _variant_sources(scan: Scan, finding: Finding) -> dict[str, dict[str, str]]:
    variants = {"original": scan.sources}
    if finding.patch:
        patched = {**scan.sources, finding.patch.file: finding.patch.patched_source}
        variants[f"patch-{finding.patch.id}"] = patched
    return variants


def _ledger_index(entries: list[dict]) -> dict[str, str]:
    """run_id -> hash of the ledger entry that recorded it."""
    index = {}
    for entry in entries:
        payload = entry["payload"]
        run = payload.get("run") or {}
        if run.get("run_id"):
            index[run["run_id"]] = entry["entry_hash"]
        for check in payload.get("checks") or []:
            if check.get("run"):
                index[check["run"]["run_id"]] = entry["entry_hash"]
    return index


def _candidate_tests(scan: Scan, finding: Finding) -> dict[str, tuple[str, str | None]]:
    """test sha256 -> (source, exercised key) for every test this finding's runs used."""
    tests = {}
    exploit = build_template(finding, scan.sources)
    if finding.verification.test_source:
        key = exploit.exercised_key if exploit else None
        tests[sha256_text(finding.verification.test_source)] = (
            finding.verification.test_source,
            key,
        )
    if exploit:
        tests[sha256_text(exploit.source)] = (exploit.source, exploit.exercised_key)
    legit = regression_template(finding, scan.sources)
    if legit:
        tests[sha256_text(legit.source)] = (legit.source, None)
    return tests


def finding_claims(scan: Scan, finding: Finding, index: dict[str, str]) -> list[Claim]:
    """Every executed run of this finding whose test and sources can be reconstructed."""
    variants = {sources_digest(src): name for name, src in _variant_sources(scan, finding).items()}
    tests = _candidate_tests(scan, finding)
    runs = []
    if finding.verification.run:
        runs.append(("exploit", "exploit test on the original source", finding.verification.run))
    if finding.remediation:
        runs += [("patch", c.name, c.run) for c in finding.remediation.checks if c.run]
    claims = []
    for kind, description, run in runs:
        if run.test_sha256 not in tests or run.source_sha256 not in variants:
            continue
        claims.append(
            Claim(
                id=f"{kind}:{finding.id}:{run.run_id}",
                finding_id=finding.id,
                title=finding.title,
                description=f"{finding.title}: {description}",
                variant=variants[run.source_sha256],
                test_path=f"tests/{run.test_sha256[:16]}.t.sol",
                test_file=run.test_file,
                test_contract=run.test_contract,
                test_function=run.test_function,
                test_sha256=run.test_sha256,
                sources_sha256=run.source_sha256,
                expected_outcome=run.outcome,
                exercised_key=tests[run.test_sha256][1],
                run_id=run.run_id,
                ledger_entry=index.get(run.run_id),
            )
        )
    return claims


def build_bundle(scan: Scan, ledger: EvidenceLedger) -> tuple[bytes, dict]:
    entries = [e.model_dump(mode="json") for e in ledger.entries(scan.id)]
    chain = ledger.verify_chain(scan.id).model_dump()
    index = _ledger_index(entries)
    files: dict[str, bytes] = {}
    claims: list[Claim] = []
    variants: dict[str, list[str]] = {}
    for finding in scan.findings:
        new = finding_claims(scan, finding, index)
        if not new:
            continue
        claims += new
        tests = _candidate_tests(scan, finding)
        for claim in new:
            files[claim.test_path] = tests[claim.test_sha256][0].encode()
        for name, sources in _variant_sources(scan, finding).items():
            if name in variants or not any(c.variant == name for c in new):
                continue
            variants[name] = []
            for rel, code in sources.items():
                path = f"sources/{name}/{Path(rel).name}"
                files[path] = code.encode()
                variants[name].append(path)
    files["ledger.json"] = json.dumps({"chain": chain, "entries": entries}, indent=1).encode()
    files["report.md"] = build_markdown_report(scan, entries, chain).encode()
    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "generator": "AuditLens",
        "created_at": time.time(),
        "scan": {"id": scan.id, "name": scan.name, "compiler": scan.compiler},
        "forge_version": forge_version(),
        "ledger_head": chain["head"],
        "variants": variants,
        "claims": [c.model_dump() for c in claims],
        "files": {path: sha256_text_bytes(data) for path, data in sorted(files.items())},
        "guarantee": __doc__.split("Guarantees: ", 1)[1].strip(),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=1))
        for path, data in sorted(files.items()):
            archive.writestr(path, data)
    return buffer.getvalue(), manifest


def sha256_text_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return bool(parts) and not PurePosixPath(path).is_absolute() and ".." not in parts


def _read_members(data: bytes) -> tuple[dict[str, bytes], list[str]]:
    """Read a bundle without extracting it; enforces size, count and path limits."""
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError(f"Bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ValueError(f"Not a valid bundle zip: {e}") from e
    infos = [i for i in archive.infolist() if not i.is_dir()]
    if len(infos) > MAX_MEMBERS:
        raise ValueError(f"Bundle has more than {MAX_MEMBERS} files")
    if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_BYTES:
        raise ValueError("Bundle expands beyond the allowed size")
    problems = [f"unsafe path: {i.filename}" for i in infos if not _safe_path(i.filename)]
    members = {i.filename: archive.read(i) for i in infos if _safe_path(i.filename)}
    if "manifest.json" not in members:
        raise ValueError("Bundle has no manifest.json")
    return members, problems


def _integrity(members: dict[str, bytes], manifest: dict) -> list[str]:
    problems = []
    listed = manifest.get("files") or {}
    for path, digest in listed.items():
        if not _safe_path(path):
            problems.append(f"unsafe path in manifest: {path}")
        elif path not in members:
            problems.append(f"missing file: {path}")
        elif sha256_text_bytes(members[path]) != digest:
            problems.append(f"hash mismatch: {path}")
    extra = set(members) - set(listed) - {"manifest.json"}
    problems += [f"unlisted file: {path}" for path in sorted(extra)]
    return problems


def _variant_from_members(members: dict[str, bytes], paths: list[str]) -> dict[str, str]:
    return {PurePosixPath(p).name: members[p].decode() for p in paths if p in members}


def _claim_problems(claims: list[Claim], members: dict, variants: dict, hashes: set) -> list[str]:
    problems = []
    for claim in claims:
        test = members.get(claim.test_path, b"")
        if sha256_text_bytes(test) != claim.test_sha256:
            problems.append(f"{claim.id}: test does not match the recorded test hash")
        sources = variants.get(claim.variant)
        if sources is None or sources_digest(sources) != claim.sources_sha256:
            problems.append(f"{claim.id}: sources do not match the recorded source digest")
        if claim.ledger_entry not in hashes:
            problems.append(f"{claim.id}: run {claim.run_id} is not recorded in the ledger")
    return problems


def _execute(claims: list[Claim], members: dict, variants: dict, workdir: Path) -> dict:
    """Run each distinct (sources, test) pair once; returns claim id -> TestResult."""
    outcomes, cache = {}, {}
    for claim in claims:
        key = (claim.variant, claim.test_sha256)
        if key not in cache:
            tests = {claim.test_file: members[claim.test_path].decode()}
            suite = execute_suite(workdir / f"run{len(cache)}", variants[claim.variant], tests)
            cache[key] = suite.result(claim.test_file, claim.test_contract, claim.test_function)
        outcomes[claim.id] = cache[key]
    return outcomes


def verify_bundle(data: bytes, workdir: Path) -> BundleVerification:
    started = time.monotonic()
    members, problems = _read_members(data)
    manifest = json.loads(members["manifest.json"])
    claims = [Claim.model_validate(c) for c in manifest.get("claims", [])]
    problems += _integrity(members, manifest)
    variants = {
        name: _variant_from_members(members, paths)
        for name, paths in (manifest.get("variants") or {}).items()
    }
    ledger = json.loads(members.get("ledger.json", b'{"entries": []}'))
    chain = verify_entries(ledger.get("entries", [])).model_dump()
    if not chain["valid"]:
        problems.append(f"ledger chain broken at entry #{chain['broken_at']}")
    hashes = {e["entry_hash"] for e in ledger.get("entries", [])}
    problems += _claim_problems(claims, members, variants, hashes)
    environment = {"forge_version": forge_version(), "sandboxed": sandbox_available()}
    base = {
        "bundle_sha256": sha256_text_bytes(data),
        "scan_name": (manifest.get("scan") or {}).get("name", ""),
        "integrity_problems": problems,
        "ledger": chain,
        "environment": environment,
    }
    if problems:
        return BundleVerification(
            verdict="tampered",
            summary=f"{len(problems)} integrity problem(s); claims were not re-executed.",
            duration_s=round(time.monotonic() - started, 2),
            **base,
        )
    available, reason = foundry_available()
    if not available:
        return BundleVerification(
            verdict="integrity_only",
            summary=f"Hashes and ledger verified; claims not re-executed ({reason}).",
            duration_s=round(time.monotonic() - started, 2),
            **base,
        )
    outcomes = _execute(claims, members, variants, workdir)
    results = [
        ClaimResult(
            claim_id=c.id,
            description=c.description,
            expected=c.expected_outcome,
            actual=outcomes[c.id].outcome,
            reproduced=outcomes[c.id].outcome == c.expected_outcome,
            detail=(outcomes[c.id].reason or "").splitlines()[0][:240]
            if outcomes[c.id].reason
            else "",
        )
        for c in claims
    ]
    reproduced = sum(r.reproduced for r in results)
    verdict = "reproduced" if reproduced == len(results) else "mismatch"
    return BundleVerification(
        verdict=verdict,
        summary=f"{reproduced}/{len(results)} recorded claims reproduced by re-execution.",
        claims=results,
        duration_s=round(time.monotonic() - started, 2),
        **base,
    )


def _recheck_verdict(claim: Claim, result) -> tuple[str, str]:
    if result.outcome == "passed":
        return "exploitable", "The proven exploit succeeds again: regression."
    if result.outcome == "property_held":
        exercised = claim.exercised_key is None or int(
            result.observations.get(claim.exercised_key, "0")
        )
        if exercised:
            return "blocked", "The exploit ran and its security assertion failed: still fixed."
        return "inconclusive", f"The attack path was not exercised ({claim.exercised_key} = 0)."
    if result.outcome in ("compile_error", "missing"):
        return "inconclusive", (
            "The exploit test no longer compiles against this version (renamed contract, "
            f"function or file?); run a fresh scan. {result.reason or ''}".strip()
        )
    return "inconclusive", (
        f"The exploit test did not reach its security assertion ({result.outcome}): "
        f"{result.reason or 'no reason given'}"
    )


def recheck(
    claims: list[Claim], tests: dict[str, str], new_sources: dict[str, str], workdir: Path
) -> Recheck:
    """Run every proven exploit (claims that originally passed) against new sources."""
    started = time.monotonic()
    proven = [c for c in claims if c.id.startswith("exploit:") and c.expected_outcome == "passed"]
    results = []
    for i, claim in enumerate(proven):
        suite = execute_suite(
            workdir / f"recheck{i}", new_sources, {claim.test_file: tests[claim.test_sha256]}
        )
        result = suite.result(claim.test_file, claim.test_contract, claim.test_function)
        verdict, detail = _recheck_verdict(claim, result)
        results.append(
            RecheckResult(
                claim_id=claim.id,
                finding_id=claim.finding_id,
                title=claim.title,
                verdict=verdict,
                outcome=result.outcome,
                detail=detail,
            )
        )
    counts = {v: sum(r.verdict == v for r in results) for v in ("exploitable", "blocked")}
    if counts["exploitable"]:
        verdict = "regression"
    elif counts["blocked"] == len(results) and results:
        verdict = "all_blocked"
    else:
        verdict = "inconclusive"
    return Recheck(
        verdict=verdict,
        summary=(
            f"{counts['exploitable']} exploitable, {counts['blocked']} blocked, "
            f"{len(results) - sum(counts.values())} inconclusive of {len(results)} proven exploits."
        ),
        new_sources_sha256=sources_digest(new_sources),
        results=results,
        duration_s=round(time.monotonic() - started, 2),
    )


def scan_recheck_inputs(scan: Scan) -> tuple[list[Claim], dict[str, str]]:
    claims, tests = [], {}
    for finding in scan.findings:
        new = finding_claims(scan, finding, {})
        claims += new
        tests.update({sha: src for sha, (src, _) in _candidate_tests(scan, finding).items()})
    return claims, tests


def bundle_recheck_inputs(data: bytes) -> tuple[list[Claim], dict[str, str]]:
    members, problems = _read_members(data)
    manifest = json.loads(members["manifest.json"])
    problems += _integrity(members, manifest)
    if problems:
        raise ValueError(f"Bundle failed integrity checks: {'; '.join(problems[:5])}")
    claims = [Claim.model_validate(c) for c in manifest.get("claims", [])]
    return claims, {c.test_sha256: members[c.test_path].decode() for c in claims}


def read_sources(paths: list[Path]) -> dict[str, str]:
    sources = {}
    for path in paths:
        files = sorted(path.rglob("*.sol")) if path.is_dir() else [path]
        for file in files:
            if file.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError(f"{file} exceeds {MAX_SOURCE_BYTES} bytes")
            sources[file.name] = file.read_text()
    if not sources:
        raise ValueError("No .sol files found in the given paths")
    return sources

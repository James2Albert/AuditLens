"""FastAPI application exposing the workbench and serving the frontend."""

import json
import time
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Path as PathParam, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from slither.tools.workbench.ai.provider import config_from_env
from slither.tools.workbench.api.store import Conflict, NotFound, ScanStore
from slither.tools.workbench.bundle import MAX_BUNDLE_BYTES
from slither.tools.workbench.models import Scan, ScanOptions
from slither.tools.workbench.reports.builder import build_markdown_report, build_summary
from slither.tools.workbench.verification.patch import MAX_PATCH_BYTES
from slither.tools.workbench.verification.runner import (
    ensure_foundry_on_path,
    foundry_available,
    sandbox_available,
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
DEMO_FILE = Path(__file__).parent.parent / "demo" / "VulnerableBank.sol"
REPORT_VERSION = 2

ScanId = Annotated[str, PathParam(max_length=64)]
FindingId = Annotated[str, PathParam(max_length=64)]


class PatchRequest(BaseModel):
    file: str | None = Field(default=None, max_length=255)
    source: str | None = Field(default=None, max_length=MAX_PATCH_BYTES)


def _options(raw: str | None) -> ScanOptions:
    if not raw:
        return ScanOptions()
    try:
        return ScanOptions.model_validate_json(raw)
    except ValidationError as e:
        raise HTTPException(400, f"Invalid scan options: {e.errors()[0]['msg']}")


def create_app(solc: str | None = None, data_dir: Path | None = None) -> FastAPI:
    ensure_foundry_on_path()
    app = FastAPI(title="AuditLens")
    store = ScanStore(artifact_root=data_dir, solc=solc)

    def scan_or_404(scan_id: str) -> Scan:
        scan = store.get(scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found")
        return scan

    def call(fn, *args):
        try:
            return fn(*args)
        except NotFound as e:
            raise HTTPException(404, str(e))
        except Conflict as e:
            raise HTTPException(409, str(e))
        except ValueError as e:
            raise HTTPException(400, str(e))

    def ledger_view(scan_id: str) -> dict:
        return {
            "chain": store.ledger.verify_chain(scan_id).model_dump(),
            "entries": [e.model_dump(mode="json") for e in store.ledger.entries(scan_id)],
        }

    @app.get("/api/status")
    def status() -> dict:
        provider = None
        try:
            config = config_from_env()
            provider = config.kind if config else None
        except Exception:
            provider = None
        foundry_ok, foundry_detail = foundry_available()
        return {
            "ai_provider": provider or "heuristic",
            "has_demo": DEMO_FILE.exists(),
            "foundry": foundry_ok,
            "sandbox": sandbox_available(),
            "foundry_detail": foundry_detail if not foundry_ok else "sandboxed verification ready",
        }

    @app.post("/api/scans")
    async def create_scan(
        files: list[UploadFile] | None = None, options: str | None = None
    ) -> JSONResponse:
        uploaded = files or []
        payload = {f.filename: await f.read() for f in uploaded}
        if not payload:
            raise HTTPException(400, "No files uploaded")
        opts = _options(options)
        name = next(iter(payload)) if len(payload) == 1 else f"{len(payload)} files"
        scan = call(store.create_scan, name, payload, opts)
        return JSONResponse({"id": scan.id})

    @app.post("/api/scans/demo")
    def create_demo_scan(options: str | None = None) -> JSONResponse:
        if not DEMO_FILE.exists():
            raise HTTPException(404, "Demo contract not found")
        opts = _options(options)
        scan = store.create_scan(DEMO_FILE.name, {DEMO_FILE.name: DEMO_FILE.read_bytes()}, opts)
        return JSONResponse({"id": scan.id})

    @app.get("/api/scans")
    def list_scans() -> list[dict]:
        return [
            {
                "id": s.id,
                "name": s.name,
                "status": s.status,
                "created_at": s.created_at,
                "findings": len(s.findings),
            }
            for s in store.list_scans()
        ]

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: ScanId) -> dict:
        scan = scan_or_404(scan_id)
        data = scan.model_dump()
        data["summary"] = build_summary(scan).model_dump()
        return data

    @app.get("/api/scans/{scan_id}/report.md")
    def report_markdown(scan_id: ScanId) -> HTMLResponse:
        scan = scan_or_404(scan_id)
        ledger = ledger_view(scan_id)
        report = build_markdown_report(scan, ledger["entries"], ledger["chain"])
        return HTMLResponse(report, media_type="text/markdown")

    @app.get("/api/scans/{scan_id}/report.json")
    def report_json(scan_id: ScanId) -> JSONResponse:
        scan = scan_or_404(scan_id)
        data = json.loads(scan.model_dump_json())
        data["report_version"] = REPORT_VERSION
        data["generated_at"] = time.time()
        data["summary"] = build_summary(scan).model_dump()
        data["evidence_ledger"] = ledger_view(scan_id)
        return JSONResponse(data)

    @app.get("/api/scans/{scan_id}/ledger")
    def ledger(scan_id: ScanId) -> dict:
        scan_or_404(scan_id)
        return ledger_view(scan_id)

    @app.get("/api/scans/{scan_id}/findings/{finding_id}/evidence")
    def evidence(scan_id: ScanId, finding_id: FindingId) -> dict:
        return call(store.evidence, scan_id, finding_id)

    @app.get("/api/scans/{scan_id}/findings/{finding_id}/test.sol")
    def test_source(scan_id: ScanId, finding_id: FindingId) -> PlainTextResponse:
        scan = scan_or_404(scan_id)
        finding = next((f for f in scan.findings if f.id == finding_id), None)
        if finding is None or not finding.verification.test_source:
            raise HTTPException(404, "No generated test for this finding")
        return PlainTextResponse(finding.verification.test_source)

    @app.post("/api/scans/{scan_id}/findings/{finding_id}/verify")
    def verify_finding(scan_id: ScanId, finding_id: FindingId) -> dict:
        return call(store.verify_finding, scan_id, finding_id).model_dump()

    @app.post("/api/scans/{scan_id}/findings/{finding_id}/patch")
    def propose_patch(
        scan_id: ScanId, finding_id: FindingId, body: PatchRequest | None = None
    ) -> dict:
        request = body or PatchRequest()
        finding = call(store.propose_patch, scan_id, finding_id, request.file, request.source)
        return finding.model_dump()

    @app.post("/api/scans/{scan_id}/findings/{finding_id}/patch/validate")
    def validate_patch(scan_id: ScanId, finding_id: FindingId) -> dict:
        return call(store.validate_patch, scan_id, finding_id).model_dump()

    @app.get("/api/scans/{scan_id}/bundle.zip")
    def bundle(scan_id: ScanId) -> Response:
        data, manifest = call(store.bundle, scan_id)
        name = f"auditlens-{scan_id}-proof-bundle.zip"
        return Response(
            data,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{name}"',
                "X-Bundle-Claims": str(len(manifest["claims"])),
            },
        )

    @app.post("/api/bundles/verify")
    async def verify_uploaded_bundle(bundle: UploadFile) -> dict:
        data = await bundle.read(MAX_BUNDLE_BYTES + 1)
        return call(store.verify_bundle, data).model_dump()

    @app.post("/api/scans/{scan_id}/recheck")
    async def recheck_scan(scan_id: ScanId, files: list[UploadFile] | None = None) -> dict:
        payload = {f.filename: await f.read() for f in files or []}
        if not payload:
            raise HTTPException(400, "No files uploaded")
        return call(store.recheck, scan_id, payload).model_dump()

    @app.delete("/api/scans/{scan_id}")
    def delete_scan(scan_id: ScanId) -> dict:
        scan_or_404(scan_id)
        store.delete(scan_id)
        return {"deleted": scan_id}

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "index.html")

    if FRONTEND_DIR.exists():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    return app

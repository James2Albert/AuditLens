"""slither-workbench / auditlens: launch the workbench, or verify and recheck proof bundles.

auditlens [--host H --port P ...]                 serve the web application
auditlens verify-bundle BUNDLE.zip [--json]       re-execute every claim in a bundle
auditlens recheck BUNDLE.zip SRC... [--json]      run proven exploits against new code
"""

import argparse
import logging
import shutil
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger("AuditLens")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AuditLens - AI-assisted smart contract security, powered by Slither.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8800, help="Bind port (default 8800)")
    parser.add_argument("--solc", default=None, help="Path to the solc binary")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Where scans, artifacts and the evidence ledger are stored "
        "(default: $XDG_DATA_HOME/auditlens or ~/.local/share/auditlens)",
    )
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    return parser.parse_args()


def _emit(result, as_json: bool, lines: list[str]) -> None:
    if as_json:
        print(result.model_dump_json(indent=2))
    else:
        print("\n".join(lines))


def verify_bundle_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="auditlens verify-bundle")
    parser.add_argument("bundle", type=Path, help="Proof bundle (.zip) exported by AuditLens")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)
    from slither.tools.workbench.bundle import verify_bundle
    from slither.tools.workbench.verification.runner import ensure_foundry_on_path

    ensure_foundry_on_path()
    with tempfile.TemporaryDirectory(prefix="auditlens-verify-") as tmp:
        result = verify_bundle(args.bundle.read_bytes(), Path(tmp))
    lines = [f"{result.verdict.upper()}: {result.summary}", f"bundle sha256 {result.bundle_sha256}"]
    lines += [f"  ! {p}" for p in result.integrity_problems]
    lines += [
        f"  [{'OK' if c.reproduced else 'MISMATCH'}] {c.description}: "
        f"expected {c.expected}, got {c.actual}"
        for c in result.claims
    ]
    _emit(result, args.json, lines)
    return 0 if result.verdict == "reproduced" else 1


def recheck_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="auditlens recheck")
    parser.add_argument("bundle", type=Path, help="Proof bundle holding the proven exploits")
    parser.add_argument("sources", type=Path, nargs="+", help="New .sol files or directories")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)
    from slither.tools.workbench.bundle import bundle_recheck_inputs, read_sources, recheck
    from slither.tools.workbench.verification.runner import ensure_foundry_on_path

    ensure_foundry_on_path()
    claims, tests = bundle_recheck_inputs(args.bundle.read_bytes())
    with tempfile.TemporaryDirectory(prefix="auditlens-recheck-") as tmp:
        result = recheck(claims, tests, read_sources(args.sources), Path(tmp))
    lines = [f"{result.verdict.upper()}: {result.summary}"]
    lines += [f"  [{r.verdict.upper()}] {r.title}: {r.detail}" for r in result.results]
    _emit(result, args.json, lines)
    return {"regression": 1, "inconclusive": 2}.get(result.verdict, 0)


COMMANDS = {"verify-bundle": verify_bundle_command, "recheck": recheck_command}


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in COMMANDS:
        sys.exit(COMMANDS[sys.argv[1]](sys.argv[2:]))
    args = parse_args()
    try:
        import uvicorn
    except ImportError:
        logger.error(
            "The workbench needs FastAPI and uvicorn. Install with: pip install fastapi uvicorn"
        )
        sys.exit(1)

    from slither.tools.workbench.api.app import create_app

    solc = args.solc or shutil.which("solc")
    if not solc:
        logger.warning("solc not found on PATH; set --solc or install solc-select.")

    app = create_app(solc=solc, data_dir=args.data_dir)
    print(f"\n  AuditLens → http://{args.host}:{args.port}\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

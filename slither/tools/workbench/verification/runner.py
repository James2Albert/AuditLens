"""Sandboxed execution of controlled exploit tests via Foundry.

Safety model:
  * The LLM never supplies shell commands or raw test code (see templates.py).
  * We only ever invoke fixed `forge` argv lists - never a shell string.
  * Execution runs in a throwaway project dir, under bubblewrap when available
    (no network, read-only system, only the project dir writable), with a cleared
    environment, prlimit resource limits, wall-clock timeouts and output-size caps.
  * foundry.toml pins ffi = false and an empty fs_permissions list, so contract code
    cannot use cheatcodes to run commands or read files.
  * Results come from forge's JSON output. A compile failure, timeout, broken fixture
    or unrelated revert is never reported as evidence for or against a vulnerability.
"""

import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from slither.tools.workbench.models import (
    ExecutionRun,
    Finding,
    Verification,
    VerificationStatus,
)
from slither.tools.workbench.verification.impact import measure
from slither.tools.workbench.verification.templates import (
    FORGE_STD_REMAPPING,
    NOT_REPRODUCED_MARKER,
    UNDETERMINED_MARKER,
    ExploitTemplate,
    build_template,
)

EXECUTION_TIMEOUT_S = 120
MAX_LOG_CHARS = 20000
MAX_TRACE_CHARS = 12000
MAX_FILE_BYTES = 256 * 1024 * 1024
LOG_LINE = re.compile(r"^\s*(\w+): (-?\d+)$")
LOG_ARRAY = re.compile(r"^\s*(\w+): \[([-\d,\s]*)\]$")
PASSTHROUGH_ENV = ("SVM_ROOT", "XDG_DATA_HOME")


def ensure_foundry_on_path() -> None:
    """Prepend the default Foundry bin dir to PATH so child forge processes are found."""
    if shutil.which("forge"):
        return
    default = Path.home() / ".foundry" / "bin"
    if (default / "forge").exists():
        os.environ["PATH"] = f"{default}{os.pathsep}{os.environ.get('PATH', '')}"


def foundry_available() -> tuple[bool, str]:
    forge = shutil.which("forge")
    if not forge:
        return False, "forge not found on PATH"
    if _vendored_forge_std() is None:
        return False, "forge-std library not vendored for offline use"
    if _solc_cache_dir() is None:
        return False, "no solc cache found; run 'forge build' once to download solc"
    return True, forge


def sandbox_available() -> bool:
    return shutil.which("bwrap") is not None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def sources_digest(sources: dict[str, str]) -> str:
    """Stable digest over every (path, content) pair, independent of dict order."""
    digest = hashlib.sha256()
    for name in sorted(sources):
        digest.update(name.encode() + b"\0" + sources[name].encode() + b"\0")
    return digest.hexdigest()


@functools.lru_cache(maxsize=1)
def forge_version() -> str:
    forge = shutil.which("forge")
    if not forge:
        return ""
    try:
        proc = subprocess.run(  # nosec: fixed argv, no shell
            [forge, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.splitlines()[0].strip() if proc.stdout else ""


def _vendored_forge_std() -> Path | None:
    candidate = Path(__file__).parent / "vendor" / "forge-std"
    return candidate if (candidate / "src" / "Test.sol").exists() else None


def _solc_cache_dir() -> Path | None:
    """Where forge/svm keeps downloaded solc binaries, so the sandbox can bind it read-only."""
    candidates = []
    if os.environ.get("SVM_ROOT"):
        candidates.append(Path(os.environ["SVM_ROOT"]))
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        candidates.append(Path(xdg) / "svm")
    candidates += [Path.home() / ".local" / "share" / "svm", Path.home() / ".svm"]
    return next((c for c in candidates if c.exists()), None)


def _foundry_bin_dir() -> Path | None:
    forge = shutil.which("forge")
    return Path(forge).resolve().parent if forge else None


def _bind_ro(path: Path | None) -> list[str]:
    return ["--ro-bind", str(path), str(path)] if path and path.exists() else []


def _child_env() -> dict[str, str]:
    """Minimal environment: API keys and other secrets in the server env never reach forge."""
    env = {
        "PATH": f"{_foundry_bin_dir()}:/usr/bin:/bin",
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "NO_COLOR": "1",
        "FOUNDRY_OFFLINE": "true",
    }
    env.update({k: os.environ[k] for k in PASSTHROUGH_ENV if os.environ.get(k)})
    return env


def _sandbox_prefix(workdir: Path) -> list[str]:
    """Wrap forge in bubblewrap: no network, read-only system, writable workdir only."""
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return []
    args = [
        bwrap,
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    # Recreate the merged-/usr layout inside the sandbox.
    for link, target in (
        ("/bin", "usr/bin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
        ("/sbin", "usr/sbin"),
    ):
        if Path(link).is_symlink():
            args += ["--symlink", target, link]
        else:
            args += _bind_ro(Path(link))
    args += _bind_ro(_foundry_bin_dir())
    args += _bind_ro(_solc_cache_dir())
    args += _bind_ro(Path.home() / ".foundry")
    # tmpfs on /tmp must come BEFORE binding the workdir, or a workdir under /tmp
    # gets shadowed by the empty tmpfs.
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    args += ["--bind", str(workdir), str(workdir), "--chdir", str(workdir)]
    for key, value in _child_env().items():
        args += ["--setenv", key, value]
    return args


def _limits_prefix() -> list[str]:
    prlimit = shutil.which("prlimit")
    if not prlimit:
        return []
    return [
        prlimit,
        f"--cpu={int(EXECUTION_TIMEOUT_S) + 1}",
        f"--fsize={MAX_FILE_BYTES}",
        "--core=0",
        "--nofile=1024",
        "--",
    ]


def write_project(workdir: Path, sources: dict[str, str], tests: dict[str, str]) -> None:
    for sub in ("src", "test", "lib"):
        (workdir / sub).mkdir(parents=True, exist_ok=True)
    for rel, code in sources.items():
        (workdir / "src" / Path(rel).name).write_text(code)
    for rel, code in tests.items():
        (workdir / "test" / Path(rel).name).write_text(code)
    (workdir / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\nlibs = ['lib']\n"
        f"remappings = ['{FORGE_STD_REMAPPING}']\noffline = true\n"
        "ffi = false\nfs_permissions = []\n"
    )
    forge_std = _vendored_forge_std()
    target = workdir / "lib" / "forge-std"
    if forge_std and not target.exists():
        shutil.copytree(forge_std, target)


@dataclass
class ProcessResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_s: float = 0.0

    @property
    def text(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()[:MAX_LOG_CHARS]


def run_forge(workdir: Path, forge_args: list[str]) -> ProcessResult:
    forge = shutil.which("forge") or "forge"
    sandbox = _sandbox_prefix(workdir)
    argv = _limits_prefix() + sandbox + [forge, *forge_args]
    started = time.monotonic()
    try:
        proc = subprocess.run(  # nosec: fixed argv, no shell
            argv,
            cwd=str(workdir),
            env=_child_env(),
            capture_output=True,
            text=True,
            timeout=EXECUTION_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ProcessResult(
            [forge, *forge_args],
            None,
            "",
            f"Execution exceeded {EXECUTION_TIMEOUT_S}s and was terminated.",
            timed_out=True,
            duration_s=time.monotonic() - started,
        )
    except OSError as e:
        return ProcessResult(
            [forge, *forge_args],
            None,
            "",
            f"Could not start forge: {e}",
            duration_s=time.monotonic() - started,
        )
    return ProcessResult(
        [forge, *forge_args],
        proc.returncode,
        proc.stdout,
        proc.stderr,
        duration_s=time.monotonic() - started,
    )


@dataclass
class TestResult:
    """Outcome of one Foundry test function.

    outcome is one of: passed, property_held, undetermined, reverted, setup_failed,
    compile_error, timeout, infra_error, missing.
    """

    __test__ = False

    outcome: str
    reason: str | None = None
    observations: dict[str, str] = field(default_factory=dict)


@dataclass
class SuiteRun:
    build: ProcessResult
    test: ProcessResult | None
    results: dict[str, TestResult]
    compiled: bool
    sandboxed: bool
    started_at: float

    def result(self, test_file: str, contract: str, function: str) -> TestResult:
        if self.build.timed_out or (self.test and self.test.timed_out):
            return TestResult("timeout", f"Execution exceeded {EXECUTION_TIMEOUT_S}s")
        if not self.compiled:
            return TestResult("compile_error", first_error(self.build.text))
        if self.test is None or not self.results:
            detail = self.test.text[-400:] if self.test else "no output"
            return TestResult("infra_error", f"forge produced no parseable result: {detail}")
        setup = self.results.get(f"{test_file}:{contract}::setUp")
        if setup is not None:
            return TestResult("setup_failed", f"setUp() failed: {setup.reason}", setup.observations)
        key = f"{test_file}:{contract}::{function}"
        return self.results.get(key, TestResult("missing", f"{key} was not executed"))


def first_error(text: str) -> str:
    lines = [l for l in text.splitlines() if l.strip()]
    start = next((i for i, l in enumerate(lines) if "Error" in l), 0)
    return "\n".join(lines[start : start + 6])[:800] or "compilation failed"


def _observations(decoded_logs: list[str]) -> dict[str, str]:
    obs = {}
    for line in decoded_logs:
        match = LOG_LINE.match(line)
        if match:
            obs[match.group(1)] = match.group(2)
            continue
        array = LOG_ARRAY.match(line)
        if array:
            obs[array.group(1)] = ",".join(v.strip() for v in array.group(2).split(",") if v.strip())
    return obs


def _test_outcome(raw: dict) -> TestResult:
    obs = _observations(raw.get("decoded_logs") or [])
    reason = raw.get("reason")
    status = raw.get("status")
    if status == "Success":
        return TestResult("passed", None, obs)
    if status != "Failure":
        return TestResult("infra_error", f"unexpected test status {status!r}", obs)
    text = reason or ""
    if NOT_REPRODUCED_MARKER in text:
        return TestResult("property_held", text, obs)
    if UNDETERMINED_MARKER in text:
        return TestResult("undetermined", text, obs)
    if "setup failed" in text.lower():
        return TestResult("setup_failed", text, obs)
    return TestResult("reverted", text or "test failed without a reason", obs)


def parse_test_json(stdout: str) -> dict[str, TestResult]:
    """Map 'test/File.t.sol:Contract::fn' -> TestResult from `forge test --json` output."""
    start = stdout.find("{")
    if start < 0:
        return {}
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return {}
    results = {}
    for suite, body in data.items():
        for name, raw in (body.get("test_results") or {}).items():
            results[f"{suite}::{name.split('(')[0]}"] = _test_outcome(raw)
    return results


def execute_suite(workdir: Path, sources: dict[str, str], tests: dict[str, str]) -> SuiteRun:
    """Compile and run a throwaway Foundry project; never touches the user's files."""
    started = time.time()
    write_project(workdir, sources, tests)
    build = run_forge(workdir, ["build", "--offline", "--color", "never"])
    compiled = build.returncode == 0 and not build.timed_out
    test = None
    results: dict[str, TestResult] = {}
    if compiled:
        test = run_forge(workdir, ["test", "--offline", "--json", "-vv"])
        if not test.timed_out:
            results = parse_test_json(test.stdout)
    return SuiteRun(build, test, results, compiled, sandbox_available(), started)


def run_trace(workdir: Path, contract: str, function: str) -> str:
    """Human-readable call trace for one test (display only; never used for classification)."""
    proc = run_forge(
        workdir,
        [
            "test",
            "--offline",
            "--color",
            "never",
            "-vvvv",
            "--match-contract",
            contract,
            "--match-test",
            function,
        ],
    )
    if proc.timed_out:
        return "Trace run timed out."
    lines = proc.stdout.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("Traces:")), 0)
    return "\n".join(lines[start:])[:MAX_TRACE_CHARS]


STATUS_BY_OUTCOME = {
    "passed": (
        VerificationStatus.VERIFIED,
        "The exploit assertion succeeded: the security property was violated.",
    ),
    "property_held": (
        VerificationStatus.NOT_VERIFIED,
        "The attack ran but the exploit assertion failed: no violation observed.",
    ),
    "undetermined": (
        VerificationStatus.INCONCLUSIVE,
        "The test ran but cannot distinguish a protection from an unmet precondition.",
    ),
    "reverted": (
        VerificationStatus.INCONCLUSIVE,
        "The test reverted for a reason unrelated to the security assertion.",
    ),
    "setup_failed": (
        VerificationStatus.ERROR,
        "The test fixture's setUp() failed; no determination possible.",
    ),
    "compile_error": (
        VerificationStatus.ERROR,
        "The contract or generated test failed to compile.",
    ),
    "timeout": (VerificationStatus.ERROR, "Execution timed out and was terminated."),
    "infra_error": (VerificationStatus.ERROR, "Foundry did not produce a usable result."),
    "missing": (VerificationStatus.ERROR, "The expected test was not executed."),
}


def classify(
    result: TestResult, template: ExploitTemplate
) -> tuple[VerificationStatus, str, bool | None]:
    status, summary = STATUS_BY_OUTCOME[result.outcome]
    exercised = None
    if template.exercised_key and template.exercised_key in result.observations:
        exercised = int(result.observations[template.exercised_key]) > 0
    if status is VerificationStatus.NOT_VERIFIED and exercised is False:
        return (
            VerificationStatus.INCONCLUSIVE,
            "The exploit assertion failed, but the attack path was never exercised "
            f"({template.exercised_key} = 0), so the test does not show the property holds.",
            exercised,
        )
    return status, summary, exercised


def build_run(
    suite: SuiteRun,
    template_file: str,
    contract: str,
    function: str,
    test_source: str,
    sources: dict[str, str],
    result: TestResult,
) -> ExecutionRun:
    proc = suite.test or suite.build
    return ExecutionRun(
        run_id=uuid.uuid4().hex[:12],
        test_file=template_file,
        test_contract=contract,
        test_function=function,
        test_sha256=sha256_text(test_source),
        source_sha256=sources_digest(sources),
        command=proc.argv,
        forge_version=forge_version(),
        sandboxed=suite.sandboxed,
        exit_code=proc.returncode,
        started_at=suite.started_at,
        duration_s=round(suite.build.duration_s + (suite.test.duration_s if suite.test else 0), 2),
        outcome=result.outcome,
        reason=result.reason,
        log_sha256=sha256_text(suite.build.text + "\n" + (suite.test.text if suite.test else "")),
    )


def reproduction_steps(template: ExploitTemplate, files: list[str]) -> list[str]:
    names = " ".join(f"src/{Path(f).name}" for f in files)
    return [
        "forge init --no-git auditlens-repro && cd auditlens-repro   # fetches forge-std once",
        "rm -f src/Counter.sol test/Counter.t.sol script/Counter.s.sol",
        f"cp <your contracts> src/   # expected: {names}",
        f"# save the generated test (Download generated test) as {template.test_file}",
        f"forge test --match-contract {template.test_contract} "
        f"--match-test {template.test_function} -vvvv",
    ]


def _not_run(template: ExploitTemplate | None, summary: str) -> Verification:
    return Verification(
        status=VerificationStatus.INCONCLUSIVE,
        template=template.name if template else "",
        test_source=template.source if template else "",
        summary=summary,
        limitations=template.limitations if template else [],
    )


def verify(finding: Finding, sources: dict[str, str], workdir: Path) -> Verification:
    template = build_template(finding, sources)
    if template is None:
        return _not_run(None, f"No exploit template applies to this '{finding.detector}' finding.")
    available, reason = foundry_available()
    if not available:
        return _not_run(
            template, f"Foundry sandbox unavailable ({reason}); test generated but not run."
        )
    started = time.monotonic()
    rundir = workdir / uuid.uuid4().hex[:12]
    suite = execute_suite(rundir, sources, {template.test_file: template.source})
    result = suite.result(template.test_file, template.test_contract, template.test_function)
    status, summary, exercised = classify(result, template)
    run = build_run(
        suite,
        template.test_file,
        template.test_contract,
        template.test_function,
        template.source,
        sources,
        result,
    )
    if result.reason and status is not VerificationStatus.VERIFIED:
        summary = f"{summary} ({result.reason.splitlines()[0][:300]})"
    executed = result.outcome not in ("compile_error", "timeout", "infra_error", "missing")
    limitations = list(template.limitations)
    if not suite.sandboxed:
        limitations.append(
            "bubblewrap was unavailable: the test ran without network or "
            "filesystem isolation (environment was still cleared)."
        )
    return Verification(
        status=status,
        template=template.name,
        test_source=template.source,
        log=(suite.build.text + "\n" + (suite.test.text if suite.test else ""))[:MAX_LOG_CHARS],
        summary=summary,
        observations=result.observations,
        steps=[
            {
                "key": "hypothesis",
                "label": "AI / heuristic hypothesis",
                "state": "done" if finding.assessment else "skipped",
            },
            {"key": "test", "label": "Test generated from template", "state": "done"},
            {
                "key": "compile",
                "label": "Compiled",
                "state": "done" if suite.compiled else "failed",
            },
            {
                "key": "execute",
                "label": "Sandbox execution",
                "state": "done" if executed else "failed",
            },
            {"key": "result", "label": "Result", "state": status.value},
        ],
        duration_s=round(time.monotonic() - started, 2),
        run=run,
        impact=measure(template.name, result.observations) if executed else [],
        attack_exercised=exercised,
        trace=run_trace(rundir, template.test_contract, template.test_function) if executed else "",
        reproduction=reproduction_steps(template, list(sources)),
        limitations=limitations,
    )

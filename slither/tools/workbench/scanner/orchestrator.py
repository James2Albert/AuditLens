"""Scan orchestrator: drives static -> AI -> graph -> verification for one target."""

import time
from collections.abc import Callable
from pathlib import Path

from slither.exceptions import SlitherError
from slither.tools.workbench.ai.heuristic import heuristic_assess
from slither.tools.workbench.ai.provider import AIProvider, AIProviderError
from slither.tools.workbench.ai.triage import assess, needs_triage
from slither.tools.workbench.graph.attack_paths import (
    access_control_paths,
    build_graph,
    escalation_findings,
)
from slither.tools.workbench.graph.finding_paths import annotate_with_evidence, finding_paths
from slither.tools.workbench.models import (
    Scan,
    Stage,
    StageStatus,
    VerificationStatus,
)
from slither.tools.workbench.scanner.evidence import (
    IMPACT_ORDER,
    build_findings,
    collect_contracts,
    collect_sources,
    run_slither,
    source_ref,
)
from slither.tools.workbench.verification.runner import verify

ProgressFn = Callable[[Scan], None]

STAGE_DEFS = [
    ("ingest", "Contract ingestion"),
    ("compile", "Compiler detection"),
    ("slither", "Slither analysis"),
    ("ai", "AI vulnerability triage"),
    ("graph", "Attack-path analysis"),
    ("verify", "Dynamic verification"),
    ("report", "Report generation"),
]


def initial_stages(options) -> list[Stage]:
    skip = {
        "ai": not options.ai_triage,
        "graph": not options.attack_paths,
        "verify": not options.dynamic_verification,
    }
    return [
        Stage(key=k, label=l, status=StageStatus.SKIPPED if skip.get(k) else StageStatus.PENDING)
        for k, l in STAGE_DEFS
    ]


class Orchestrator:
    def __init__(self, scan: Scan, target: Path, solc: str | None,
                 provider: AIProvider | None, workdir: Path, progress: ProgressFn) -> None:
        self.scan = scan
        self.target = target
        self.solc = solc
        self.provider = provider
        self.workdir = workdir
        self.progress = progress

    def _stage(self, key: str) -> Stage:
        return next(s for s in self.scan.stages if s.key == key)

    def _set(self, key: str, status: StageStatus, detail: str = "") -> None:
        stage = self._stage(key)
        stage.status = status
        if detail:
            stage.detail = detail
        self.progress(self.scan)

    def _enabled(self, key: str) -> bool:
        return self._stage(key).status is not StageStatus.SKIPPED

    def run(self) -> None:
        self.scan.status = "running"
        try:
            self._run_static()
            if self._enabled("graph"):
                self._run_graph()
            if self._enabled("ai"):
                self._run_ai()
            if self._enabled("verify"):
                self._run_verification()
            self._run_report()
            self.scan.status = "done"
        except SlitherError as e:
            self.scan.status = "failed"
            self.scan.error = f"Slither analysis failed: {e}"
            for stage in self.scan.stages:
                if stage.status is StageStatus.RUNNING:
                    self._set(stage.key, StageStatus.FAILED, str(e))
        finally:
            self.progress(self.scan)

    def _run_static(self) -> None:
        root = self.target.parent if self.target.is_file() else self.target
        self._set("ingest", StageStatus.RUNNING)
        self._set("ingest", StageStatus.DONE, f"Target: {self.target.name}")
        self._set("compile", StageStatus.RUNNING)
        slither, results = run_slither(self.target, self.solc)
        self.scan.compiler = _detect_compiler(slither)
        self._set("compile", StageStatus.DONE, self.scan.compiler)
        self._set("slither", StageStatus.RUNNING)
        self.scan.sources = collect_sources(slither, root)
        self.scan.contracts = collect_contracts(slither, root)
        self.scan.findings = build_findings(slither, results, root)
        self._slither = slither
        self._root = root
        self._set("slither", StageStatus.DONE, f"{len(self.scan.findings)} findings discovered")

    def _run_graph(self) -> None:
        self._set("graph", StageStatus.RUNNING)
        graph = build_graph(self._slither)
        paths = access_control_paths(graph, self.scan.findings,
                                     lambda o: source_ref(o, self._root))
        derived = escalation_findings(graph, paths, self._root)
        self.scan.findings = sorted(self.scan.findings + derived,
                                    key=lambda f: (IMPACT_ORDER.get(f.impact, 9), f.detector))
        paths += finding_paths(graph, self.scan.findings)
        self.scan.attack_paths = paths
        self._set("graph", StageStatus.DONE,
                  f"{len(paths)} attack paths identified, "
                  f"{len(derived)} escalation finding(s) derived")

    def _run_ai(self) -> None:
        self._set("ai", StageStatus.RUNNING)
        candidates = [f for f in self.scan.findings if needs_triage(f)]
        self.scan.ai_provider = self.provider.name if self.provider else "heuristic"
        exploitable = 0
        for index, finding in enumerate(candidates, 1):
            finding.assessment = self._assess_one(finding)
            if finding.assessment.classification.value.endswith("exploitable") and \
                    "unlikely" not in finding.assessment.classification.value:
                exploitable += 1
            self._set("ai", StageStatus.RUNNING, f"Triaged {index}/{len(candidates)} findings")
        label = self.provider.name if self.provider else "heuristic rules"
        self._set("ai", StageStatus.DONE,
                  f"{exploitable} of {len(candidates)} flagged exploitable ({label})")

    def _assess_one(self, finding):
        if self.provider is None:
            return heuristic_assess(finding)
        try:
            return assess(self.provider, finding, self.scan.attack_paths)
        except AIProviderError:
            return heuristic_assess(finding)

    def _run_verification(self) -> None:
        self._set("verify", StageStatus.RUNNING)
        targets = [f for f in self.scan.findings
                   if f.category in ("reentrancy", "access-control")]
        verified = 0
        for index, finding in enumerate(targets, 1):
            finding.verification = verify(finding, self.scan.sources, self.workdir / finding.id)
            if finding.verification.status is VerificationStatus.VERIFIED:
                verified += 1
            self._set("verify", StageStatus.RUNNING, f"Verified {index}/{len(targets)}")
        annotate_with_evidence(self.scan.attack_paths, self.scan.findings)
        self._set("verify", StageStatus.DONE, f"{verified} exploit(s) verified")

    def _run_report(self) -> None:
        if self._stage("report").status is StageStatus.SKIPPED:
            return
        self._set("report", StageStatus.RUNNING)
        self._set("report", StageStatus.DONE, "Report ready")


def _detect_compiler(slither) -> str:
    for unit in slither.compilation_units:
        v = getattr(unit.crytic_compile_compilation_unit.compiler_version, "version", None)
        if v:
            return f"solc {v}"
    return "solc"

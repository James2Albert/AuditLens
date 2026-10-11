"""Data model shared by the scanner, AI, graph, verification and API layers.

Four kinds of information are kept strictly apart:
  * static       - produced deterministically by Slither (Finding, FunctionEvidence)
  * ai           - hypotheses produced by a language model (Assessment)
  * dynamic      - results of executing a controlled test (Verification, ExecutionRun)
  * remediation  - results of validating a candidate fix (PatchProposal, PatchValidation)
"""

from enum import Enum

from pydantic import BaseModel, Field


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"


class VerificationStatus(str, Enum):
    NOT_RUN = "not_run"
    VERIFIED = "verified_exploit"
    NOT_VERIFIED = "not_verified"
    INCONCLUSIVE = "inconclusive"
    ERROR = "verification_error"


class Exploitability(str, Enum):
    LIKELY = "likely_exploitable"
    POSSIBLE = "possibly_exploitable"
    UNLIKELY = "unlikely_exploitable"
    FALSE_POSITIVE = "likely_false_positive"
    UNKNOWN = "unknown"


class SourceRef(BaseModel):
    file: str
    lines: list[int] = Field(default_factory=list)
    label: str = ""
    role: str = "primary"
    variable: str | None = None


class FunctionEvidence(BaseModel):
    """Facts Slither knows about a function; this is what the AI reasons over."""

    contract: str
    name: str
    signature: str
    visibility: str
    payable: bool = False
    modifiers: list[str] = Field(default_factory=list)
    is_protected: bool = False
    checks_msg_sender: bool = False
    state_read: list[str] = Field(default_factory=list)
    state_written: list[str] = Field(default_factory=list)
    external_calls: list[str] = Field(default_factory=list)
    low_level_calls: list[str] = Field(default_factory=list)
    sends_eth: bool = False
    internal_calls: list[str] = Field(default_factory=list)
    callers: list[str] = Field(default_factory=list)
    source: SourceRef | None = None
    code: str = ""


class Assessment(BaseModel):
    """A model's structured hypothesis about one finding. Never treated as fact."""

    classification: Exploitability = Exploitability.UNKNOWN
    confidence: int = Field(default=0, ge=0, le=100)
    summary: str = ""
    why_it_matters: str = ""
    preconditions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    attack_steps: list[str] = Field(default_factory=list)
    affected_state: list[str] = Field(default_factory=list)
    provider: str = ""
    model: str = ""
    raw_error: str | None = None


class ImpactMeasurement(BaseModel):
    """A value read from an executed test. Never an estimate of production impact."""

    key: str
    label: str
    before: str | None = None
    after: str | None = None
    delta: str | None = None
    unit: str = ""
    violated: bool | None = None
    basis: str = "Observed in the local Foundry test fixture"


class ExecutionRun(BaseModel):
    """Provenance of one sandboxed test execution."""

    run_id: str
    test_file: str
    test_contract: str
    test_function: str
    test_sha256: str
    source_sha256: str
    command: list[str] = Field(default_factory=list)
    forge_version: str = ""
    sandboxed: bool = False
    exit_code: int | None = None
    started_at: float = 0.0
    duration_s: float = 0.0
    outcome: str = ""
    reason: str | None = None
    log_sha256: str = ""


class Verification(BaseModel):
    status: VerificationStatus = VerificationStatus.NOT_RUN
    template: str = ""
    test_source: str = ""
    log: str = ""
    summary: str = ""
    observations: dict[str, str] = Field(default_factory=dict)
    steps: list[dict[str, str]] = Field(default_factory=list)
    duration_s: float = 0.0
    run: ExecutionRun | None = None
    impact: list[ImpactMeasurement] = Field(default_factory=list)
    attack_exercised: bool | None = None
    trace: str = ""
    reproduction: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PatchProposal(BaseModel):
    """A candidate fix. It is only ever applied inside a throwaway validation workspace."""

    id: str
    finding_id: str
    origin: str
    strategy: str
    description: str
    file: str
    original_sha256: str
    patched_sha256: str
    diff: str
    patched_source: str


class CheckResult(BaseModel):
    name: str
    status: str = "skipped"
    detail: str = ""
    run: ExecutionRun | None = None
    observations: dict[str, str] = Field(default_factory=dict)


class PatchStatus(str, Enum):
    VALIDATED = "validated"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class PatchValidation(BaseModel):
    id: str
    finding_id: str
    patch_id: str
    status: PatchStatus
    summary: str
    checks: list[CheckResult] = Field(default_factory=list)
    tested_properties: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    created_at: float = 0.0
    duration_s: float = 0.0


class Finding(BaseModel):
    id: str
    detector: str
    title: str
    impact: str
    confidence: str
    description: str
    contract: str | None = None
    function: str | None = None
    location: SourceRef | None = None
    related: list[SourceRef] = Field(default_factory=list)
    evidence: FunctionEvidence | None = None
    category: str | None = None
    origin: str = "slither"
    wiki_description: str = ""
    wiki_recommendation: str = ""
    assessment: Assessment | None = None
    verification: Verification = Field(default_factory=Verification)
    patch: PatchProposal | None = None
    remediation: PatchValidation | None = None


class PathNode(BaseModel):
    id: str
    label: str
    kind: str
    function: str | None = None
    source: SourceRef | None = None
    reason: str = ""


class AttackPath(BaseModel):
    id: str
    category: str
    title: str
    finding_ids: list[str] = Field(default_factory=list)
    nodes: list[PathNode] = Field(default_factory=list)
    edges: list[tuple[str, str, str]] = Field(default_factory=list)
    narrative: list[str] = Field(default_factory=list)
    derived_from: str = "static"
    evidence_status: str = "static-hypothesis"
    evidence_note: str = "Inferred from the static graph; connectivity alone does not prove exploitability."
    run_ids: list[str] = Field(default_factory=list)
    patch_status: str | None = None


class Stage(BaseModel):
    key: str
    label: str
    status: StageStatus = StageStatus.PENDING
    detail: str = ""


class ScanOptions(BaseModel):
    static_analysis: bool = True
    ai_triage: bool = True
    attack_paths: bool = True
    dynamic_verification: bool = True


class ContractInfo(BaseModel):
    name: str
    file: str
    kind: str
    functions: list[str] = Field(default_factory=list)


class Scan(BaseModel):
    id: str
    name: str
    created_at: float
    status: str = "queued"
    error: str | None = None
    options: ScanOptions = Field(default_factory=ScanOptions)
    compiler: str = ""
    stages: list[Stage] = Field(default_factory=list)
    sources: dict[str, str] = Field(default_factory=dict)
    contracts: list[ContractInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    ai_provider: str = ""

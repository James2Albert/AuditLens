"""Run Slither through its Python API and turn detector output into structured evidence."""

import inspect
import re
from pathlib import Path

from slither import Slither
from slither.core.declarations import Contract, Function, FunctionContract
from slither.detectors import all_detectors
from slither.detectors.abstract_detector import AbstractDetector
from slither.slithir.operations import LowLevelCall
from slither.tools.workbench.models import (
    ContractInfo,
    Finding,
    FunctionEvidence,
    SourceRef,
)

CATEGORY_BY_DETECTOR = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "unchecked-lowlevel": "unchecked-call",
    "unchecked-send": "unchecked-call",
    "unchecked-transfer": "unchecked-call",
    "suicidal": "access-control",
    "arbitrary-send-eth": "access-control",
    "unprotected-upgrade": "access-control",
    "controlled-delegatecall": "access-control",
    "protected-vars": "access-control",
    "tx-origin": "access-control",
}

IMPACT_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}
# Slither descriptions embed paths relative to the server's cwd; keep only the file name.
SOURCE_PATH = re.compile(r"[^\s()]*/([^/\s()]+\.(?:sol|vy)#)")


def detector_classes() -> dict[str, type[AbstractDetector]]:
    classes = [getattr(all_detectors, name) for name in dir(all_detectors)]
    return {
        d.ARGUMENT: d
        for d in classes
        if inspect.isclass(d) and issubclass(d, AbstractDetector) and d is not AbstractDetector
    }


def run_slither(target: Path, solc: str | None) -> tuple[Slither, list[dict]]:
    kwargs = {"compile_force_framework": "solc"}
    if solc:
        kwargs["solc"] = solc
    slither = Slither(str(target), **kwargs)
    for detector in detector_classes().values():
        slither.register_detector(detector)
    results = [result for per_detector in slither.run_detectors() for result in per_detector]
    return slither, results


def relative_file(absolute: str, root: Path) -> str:
    try:
        return str(Path(absolute).resolve().relative_to(root.resolve()))
    except ValueError:
        return Path(absolute).name


def collect_sources(slither: Slither, root: Path) -> dict[str, str]:
    return {relative_file(path, root): code for path, code in slither.source_code.items()}


def collect_contracts(slither: Slither, root: Path) -> list[ContractInfo]:
    infos = []
    for contract in slither.contracts_derived:
        kind = "interface" if contract.is_interface else "library" if contract.is_library else "contract"
        infos.append(
            ContractInfo(
                name=contract.name,
                file=relative_file(contract.source_mapping.filename.absolute, root),
                kind=kind,
                functions=[f.full_name for f in contract.functions_declared],
            )
        )
    return infos


def source_ref(obj, root: Path, label: str = "", role: str = "primary") -> SourceRef:
    mapping = obj.source_mapping
    return SourceRef(
        file=relative_file(mapping.filename.absolute, root),
        lines=list(mapping.lines),
        label=label,
        role=role,
    )


def function_evidence(function: Function, root: Path) -> FunctionEvidence:
    contract = function.contract_declarer if isinstance(function, FunctionContract) else None
    low_level = [ir for ir in function.all_low_level_calls() if isinstance(ir, LowLevelCall)]
    conditional = [str(v) for v in function.all_conditional_solidity_variables_read()]
    return FunctionEvidence(
        contract=contract.name if contract else "",
        name=function.name,
        signature=function.full_name,
        visibility=function.visibility,
        payable=function.payable,
        modifiers=[m.name for m in function.modifiers],
        is_protected=function.is_protected(),
        checks_msg_sender="msg.sender" in conditional,
        state_read=sorted({v.name for v in function.all_state_variables_read()}),
        state_written=sorted({v.name for v in function.all_state_variables_written()}),
        external_calls=sorted({str(e) for e in function.external_calls_as_expressions}),
        low_level_calls=sorted({f"{ir.destination}.{ir.function_name}" for ir in low_level}),
        sends_eth=function.can_send_eth(),
        internal_calls=sorted({c.function.name for c in function.internal_calls}),
        callers=sorted({f.canonical_name for f in function.reachable_from_functions}),
        source=source_ref(function, root, label=function.full_name),
        code=function.source_mapping.content,
    )


def _resolve_function(slither: Slither, element: dict) -> Function | None:
    fields = element.get("type_specific_fields") or {}
    if element["type"] == "function":
        contract_name = (fields.get("parent") or {}).get("name")
        signature = fields.get("signature")
    elif element["type"] == "node":
        parent = fields.get("parent") or {}
        if parent.get("type") != "function":
            return None
        parent_fields = parent.get("type_specific_fields") or {}
        contract_name = (parent_fields.get("parent") or {}).get("name")
        signature = parent_fields.get("signature")
    else:
        return None
    if not contract_name or not signature:
        return None
    for contract in slither.get_contract_from_name(contract_name):
        found = _function_by_signature(contract, signature)
        if found is not None:
            return found
    return None


def _function_by_signature(contract: Contract, signature: str) -> Function | None:
    return next((f for f in contract.functions if f.solidity_signature == signature), None)


def _element_ref(element: dict, root: Path, primary: bool) -> SourceRef:
    mapping = element["source_mapping"]
    extra = element.get("additional_fields") or {}
    role = "primary" if primary else extra.get("underlying_type", "related")
    return SourceRef(
        file=relative_file(mapping["filename_absolute"], root),
        lines=mapping.get("lines", []),
        label=element["name"],
        role=role,
        variable=extra.get("variable_name"),
    )


def build_finding(slither: Slither, result: dict, root: Path, detectors: dict) -> Finding:
    elements = [e for e in result["elements"] if e.get("source_mapping", {}).get("lines")]
    function = next((f for f in (_resolve_function(slither, e) for e in elements) if f), None)
    detector = detectors.get(result["check"])
    return Finding(
        id=result["id"][:12],
        detector=result["check"],
        title=detector.WIKI_TITLE if detector else result["check"],
        impact=result["impact"],
        confidence=result["confidence"],
        description=SOURCE_PATH.sub(r"\1", result["description"]).strip(),
        contract=function.contract_declarer.name if isinstance(function, FunctionContract) else None,
        function=function.full_name if function else None,
        location=_element_ref(elements[0], root, primary=True) if elements else None,
        related=[_element_ref(e, root, primary=False) for e in elements[1:]],
        evidence=function_evidence(function, root) if function else None,
        category=CATEGORY_BY_DETECTOR.get(result["check"]),
        wiki_description=(detector.WIKI_DESCRIPTION if detector else "").strip(),
        wiki_recommendation=(detector.WIKI_RECOMMENDATION if detector else "").strip(),
    )


def build_findings(slither: Slither, results: list[dict], root: Path) -> list[Finding]:
    detectors = detector_classes()
    findings = [build_finding(slither, r, root, detectors) for r in results]
    return sorted(findings, key=lambda f: (IMPACT_ORDER.get(f.impact, 9), f.detector))

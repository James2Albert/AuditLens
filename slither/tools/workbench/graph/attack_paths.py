"""Attack-path reasoning over a security graph built from Slither's analysis.

Graph nodes:
  attacker            - any externally owned account or contract
  fn:<canonical>      - a contract function
  var:<canonical>     - a state variable
  sink:<canonical>:k  - a sensitive operation (ETH transfer, selfdestruct, delegatecall)

Edges carry a `rel` attribute:
  calls       attacker -> unprotected entry point, or function -> internal callee
  writes      function -> state variable it writes
  authorizes  state variable -> function whose msg.sender check reads it
  reaches     function -> sensitive sink

Paths are derived deterministically; the AI layer may only annotate them.
"""

import hashlib
import itertools
from pathlib import Path

import networkx as nx

from slither import Slither
from slither.core.declarations import Contract, Function, FunctionContract
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.slithir.operations import LowLevelCall
from slither.tools.workbench.models import AttackPath, Finding, PathNode, SourceRef
from slither.tools.workbench.scanner.evidence import function_evidence, source_ref
from slither.tools.workbench.verification.templates import ESCALATION_DETECTOR

ATTACKER = "attacker"
SELFDESTRUCT = {"selfdestruct(address)", "suicide(address)"}


def _fn_id(function: Function) -> str:
    return f"fn:{function.canonical_name}"


def _is_entry_point(function: Function) -> bool:
    return (
        function.visibility in ("public", "external")
        and not function.is_constructor
        and not function.view
        and not function.pure
    )


def _guard_variables(function: Function) -> list:
    conditional = [str(v) for v in function.all_conditional_solidity_variables_read()]
    if "msg.sender" not in conditional:
        return []
    return list(function.all_conditional_state_variables_read())


def _sinks(function: Function) -> list[tuple[str, str]]:
    sinks = []
    if function.can_send_eth():
        sinks.append(("eth", "ETH transfer"))
    called = {c.function.name for c in function.all_solidity_calls()}
    if called & SELFDESTRUCT or any(
        isinstance(c.function, SolidityFunction) and c.function.name in SELFDESTRUCT
        for c in function.all_internal_calls()
    ):
        sinks.append(("selfdestruct", "selfdestruct"))
    lowlevel = [ir for ir in function.all_low_level_calls() if isinstance(ir, LowLevelCall)]
    if any(ir.function_name == "delegatecall" for ir in lowlevel):
        sinks.append(("delegatecall", "delegatecall"))
    return sinks


def _add_function(graph: nx.DiGraph, function: Function) -> None:
    node = _fn_id(function)
    graph.add_node(node, kind="function", label=function.full_name, obj=function)
    if _is_entry_point(function) and not function.is_protected():
        graph.add_edge(ATTACKER, node, rel="calls")
    for var in function.all_state_variables_written():
        graph.add_node(f"var:{var.canonical_name}", kind="state", label=var.name, obj=var)
        graph.add_edge(node, f"var:{var.canonical_name}", rel="writes")
    for var in _guard_variables(function):
        graph.add_node(f"var:{var.canonical_name}", kind="state", label=var.name, obj=var)
        graph.add_edge(f"var:{var.canonical_name}", node, rel="authorizes")
    for call in function.internal_calls:
        if isinstance(call.function, FunctionContract):
            graph.add_edge(node, _fn_id(call.function), rel="calls")
    for key, label in _sinks(function):
        sink = f"sink:{function.canonical_name}:{key}"
        graph.add_node(sink, kind="sink", label=label, sink=key, obj=function)
        graph.add_edge(node, sink, rel="reaches")


def build_graph(slither: Slither) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(ATTACKER, kind="attacker", label="Attacker")
    for contract in slither.contracts_derived:
        if contract.is_interface:
            continue
        for function in contract.functions:
            if isinstance(function, FunctionContract) and not function.is_constructor:
                _add_function(graph, function)
    return graph


def attacker_can_reach(graph: nx.DiGraph, node: str) -> list[str] | None:
    if node not in graph:
        return None
    try:
        return nx.shortest_path(graph, ATTACKER, node)
    except nx.NetworkXNoPath:
        return None


def _ref(obj, root_rel) -> SourceRef | None:
    return root_rel(obj) if obj is not None else None


def _findings_for(findings: list[Finding], functions: set[str]) -> list[str]:
    return [
        f.id
        for f in findings
        if f.function
        and f.evidence
        and f"{f.evidence.contract}.{f.evidence.signature}" in functions
    ]


def _path_node(graph: nx.DiGraph, node: str, root_rel) -> PathNode:
    data = graph.nodes[node]
    obj = data.get("obj")
    kind = {"attacker": "attacker", "state": "state-mutation", "sink": "external-call"}.get(
        data["kind"], "entry-point"
    )
    function = obj.full_name if isinstance(obj, Function) else None
    return PathNode(
        id=node, label=data["label"], kind=kind, function=function, source=_ref(obj, root_rel)
    )


def _escalation_path(graph, path, findings, root_rel, index) -> AttackPath:
    nodes = [_path_node(graph, n, root_rel) for n in path]
    edges = [(a, b, graph.edges[a, b]["rel"]) for a, b in itertools.pairwise(path)]
    guard = next(graph.nodes[n]["label"] for n in path if graph.nodes[n]["kind"] == "state")
    writer = graph.nodes[path[1]]["label"]
    privileged = graph.nodes[path[-2]]["label"]
    sink = graph.nodes[path[-1]]["label"]
    nodes[1].kind = "vulnerable-function"
    nodes[1].reason = f"Callable by anyone and writes `{guard}`, which gates privileged code."
    nodes[-2].reason = f"Guarded by a msg.sender check against `{guard}`."
    nodes[-1].reason = f"Sensitive operation: {sink}."
    functions = {
        graph.nodes[n]["obj"].canonical_name for n in path if graph.nodes[n]["kind"] == "function"
    }
    return AttackPath(
        id=f"ac-{index}",
        category="access-control",
        title=f"Privilege escalation: {writer} → {privileged}",
        finding_ids=_findings_for(findings, functions),
        nodes=nodes,
        edges=edges,
        narrative=[
            f"Attacker calls {writer}, which has no msg.sender check.",
            f"{writer} overwrites `{guard}`.",
            f"`{guard}` is the value {privileged} compares msg.sender against.",
            f"Attacker now passes the check in {privileged} and reaches {sink}.",
        ],
        derived_from="static-graph",
    )


def access_control_paths(graph, findings, root_rel) -> list[AttackPath]:
    paths = []
    sinks = [n for n, d in graph.nodes(data=True) if d["kind"] == "sink"]
    for sink in sorted(sinks):
        path = attacker_can_reach(graph, sink)
        if not path or not any(graph.nodes[n]["kind"] == "state" for n in path):
            continue
        paths.append(_escalation_path(graph, path, findings, root_rel, len(paths) + 1))
    return paths


def _escalation_nodes(path: AttackPath) -> list[str] | None:
    """Node ids of a direct attacker -> writer -> guard -> privileged -> sink path, else None."""
    ids = [n.id for n in path.nodes]
    prefixes = (ATTACKER, "fn:", "var:", "fn:", "sink:")
    if len(ids) != len(prefixes) or not all(i.startswith(p) for i, p in zip(ids, prefixes, strict=True)):
        return None
    return ids


def _escalation_finding(graph: nx.DiGraph, ids: list[str], root: Path) -> Finding | None:
    writer, guard, privileged = (graph.nodes[i]["obj"] for i in ids[1:4])
    sink = graph.nodes[ids[4]]["label"]
    if writer.contract_declarer != privileged.contract_declarer:
        return None
    key = f"{ESCALATION_DETECTOR}:{writer.canonical_name}:{privileged.canonical_name}:{sink}"
    guard_ref = source_ref(guard, root, label=guard.name, role="guard_variable")
    guard_ref.variable = guard.name
    privileged_ref = source_ref(
        privileged, root, label=privileged.full_name, role="privileged_function"
    )
    sink_ref = SourceRef(
        file=privileged_ref.file, lines=privileged_ref.lines, label=sink, role="sink"
    )
    return Finding(
        id=hashlib.sha256(key.encode()).hexdigest()[:12],
        detector=ESCALATION_DETECTOR,
        title=f"Privilege escalation: {writer.full_name} → {privileged.full_name}",
        impact="High",
        confidence="Medium",
        description=(
            f"{writer.full_name} has no msg.sender check and writes `{guard.name}`, which "
            f"{privileged.full_name} compares msg.sender against before reaching: {sink}. "
            f"Any caller can overwrite `{guard.name}` and then pass that check.\n"
            "Derived by the AuditLens graph rule from Slither's analysis; this is not the "
            "output of a Slither detector."
        ),
        contract=writer.contract_declarer.name,
        function=writer.full_name,
        location=source_ref(writer, root, label=writer.full_name),
        related=[guard_ref, privileged_ref, sink_ref],
        evidence=function_evidence(writer, root),
        category="access-control",
        origin="auditlens-graph",
        wiki_description=(
            "A function without an access check writes the state variable that another "
            "function uses to authorize msg.sender, so any caller can grant themselves the "
            "privileged role."
        ),
        wiki_recommendation=(
            f"Restrict {writer.full_name} to the current holder of `{guard.name}` (for example "
            f"`require(msg.sender == {guard.name})` or an onlyOwner modifier)."
        ),
    )


def escalation_findings(graph: nx.DiGraph, paths: list[AttackPath], root: Path) -> list[Finding]:
    """One finding per direct escalation path, linked back to that path."""
    findings = []
    for path in paths:
        ids = _escalation_nodes(path)
        finding = _escalation_finding(graph, ids, root) if ids else None
        if finding is None:
            continue
        path.finding_ids.append(finding.id)
        findings.append(finding)
    return findings

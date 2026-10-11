"""Candidate attack paths anchored on individual Slither findings."""

import networkx as nx

from slither.tools.workbench.graph.attack_paths import ATTACKER, attacker_can_reach
from slither.tools.workbench.models import (
    AttackPath,
    Finding,
    PathNode,
    SourceRef,
    VerificationStatus,
)


def _refs(finding: Finding, role: str) -> list[SourceRef]:
    return [r for r in finding.related if r.role == role]


def _fn_node(graph: nx.DiGraph, finding: Finding) -> str:
    return f"fn:{finding.evidence.contract}.{finding.evidence.signature}"


def _entry_nodes(graph: nx.DiGraph, finding: Finding) -> tuple[list[PathNode], list[str]]:
    """Attacker node(s) leading into the finding's function, honouring access checks."""
    route = attacker_can_reach(graph, _fn_node(graph, finding)) or []
    if len(route) <= 2:
        attacker = PathNode(id=ATTACKER, label="Attacker", kind="attacker",
                            reason="Any account can call this function directly.")
        return [attacker], []
    steps = [graph.nodes[n]["label"] for n in route[1:-1]]
    attacker = PathNode(id=ATTACKER, label="Attacker", kind="attacker",
                        reason=f"Gains access first via {' → '.join(steps)}.")
    return [attacker], [f"Attacker first satisfies the access check via {' → '.join(steps)}."]


def _destination_controlled(graph: nx.DiGraph, finding: Finding) -> tuple[bool, str]:
    ev = finding.evidence
    targets = [c.rsplit(".", 1)[0] for c in ev.low_level_calls] or ev.external_calls
    if any("msg.sender" in t for t in targets):
        return True, "Call target is msg.sender, which the attacker controls."
    for target in targets:
        var = f"var:{ev.contract}.{target}"
        if attacker_can_reach(graph, var):
            return True, f"`{target}` can be overwritten through an attacker-reachable path."
    return False, "Call target is not attacker-controlled according to the static graph."


def reentrancy_path(graph: nx.DiGraph, finding: Finding, index: int) -> AttackPath:
    ev = finding.evidence
    call_refs = _refs(finding, "external_calls") or _refs(finding, "external_calls_sending_eth")
    write_refs = _refs(finding, "variables_written")
    controlled, why = _destination_controlled(graph, finding)
    entry, narrative = _entry_nodes(graph, finding)
    fn = PathNode(id="entry", label=ev.signature, kind="entry-point", function=ev.signature,
                  source=ev.source, reason="Public entry point that performs the external call.")
    call = PathNode(id="call", label=call_refs[0].label if call_refs else "external call",
                    kind="external-call", function=ev.signature,
                    source=call_refs[0] if call_refs else None,
                    reason="Hands execution to another contract before state is finalised.")
    callback = PathNode(id="callback", label="attacker fallback / receive",
                        kind="attacker-controlled", reason=why)
    reenter = PathNode(id="reenter", label=f"{ev.signature} (re-entered)",
                       kind="vulnerable-function", function=ev.signature, source=ev.source,
                       reason="Runs again while the previous invocation's state is stale.")
    write = PathNode(id="write", label=write_refs[0].label if write_refs else "state update",
                     kind="state-mutation", function=ev.signature,
                     source=write_refs[0] if write_refs else None,
                     reason="State is only updated after the external call returns.")
    state = ", ".join(sorted({r.variable or r.label for r in write_refs})) or "state"
    return AttackPath(
        id=f"re-{index}",
        category="reentrancy",
        title=f"Reentrancy through {ev.signature}",
        finding_ids=[finding.id],
        nodes=[*entry, fn, call, callback, reenter, write],
        edges=[(ATTACKER, "entry", "calls"), ("entry", "call", "executes"),
               ("call", "callback", "transfers control"), ("callback", "reenter", "calls"),
               ("reenter", "call", "executes"), ("entry", "write", "writes after call")],
        narrative=[*narrative,
                   f"Attacker contract calls {ev.signature}.",
                   f"{ev.signature} performs `{call.label}` before updating {state}.",
                   f"The callee's fallback runs. {why}",
                   f"Fallback calls {ev.signature} again; {state} still hold(s) the old value.",
                   f"Only after the recursion unwinds is `{write.label}` executed."],
        derived_from="static-finding" if controlled else "static-finding (target not controlled)",
    )


def unchecked_call_path(graph: nx.DiGraph, finding: Finding, index: int) -> AttackPath:
    ev = finding.evidence
    call_ref = finding.related[0] if finding.related else finding.location
    entry, narrative = _entry_nodes(graph, finding)
    fn = PathNode(id="entry", label=ev.signature, kind="entry-point", function=ev.signature,
                  source=ev.source, reason="Function containing the unchecked call.")
    call = PathNode(id="call", label=call_ref.label if call_ref else "low-level call",
                    kind="external-call", function=ev.signature, source=call_ref,
                    reason="Return value of this call is never checked.")
    fail = PathNode(id="fail", label="call fails silently", kind="attacker-controlled",
                    reason="A reverting or out-of-gas callee makes the call return false.")
    cont = PathNode(id="continue", label="execution continues", kind="state-mutation",
                    function=ev.signature,
                    reason="The caller proceeds as if the transfer succeeded.")
    return AttackPath(
        id=f"uc-{index}",
        category="unchecked-call",
        title=f"Unchecked call in {ev.signature}",
        finding_ids=[finding.id],
        nodes=[*entry, fn, call, fail, cont],
        edges=[(ATTACKER, "entry", "calls"), ("entry", "call", "executes"),
               ("call", "fail", "returns false"), ("fail", "continue", "ignored")],
        narrative=[*narrative,
                   f"{ev.signature} performs `{call.label}`.",
                   "If the callee reverts, the call returns false instead of bubbling up.",
                   "The return value is discarded, so the failure is invisible to the caller."],
    )


PATH_STATUS_BY_VERIFICATION = {
    VerificationStatus.VERIFIED: "dynamically-demonstrated",
    VerificationStatus.NOT_VERIFIED: "not-reproduced",
}


def _path_status(finding: Finding) -> tuple[str, str]:
    v = finding.verification
    status = PATH_STATUS_BY_VERIFICATION.get(v.status, "inconclusive")
    if status == "dynamically-demonstrated" and not v.attack_exercised:
        status = "inconclusive"
    notes = {
        "dynamically-demonstrated": f"Test run {v.run.run_id} executed this path and the exploit "
                                    "assertion succeeded.",
        "not-reproduced": f"Test run {v.run.run_id} attempted this path; the exploit assertion "
                          "failed. The static warning still stands.",
        "inconclusive": f"Test run {v.run.run_id} did not decide this path ({v.status.value}).",
    }
    return status, notes[status]


def annotate_with_evidence(paths: list[AttackPath], findings: list[Finding]) -> None:
    """Attach dynamic and remediation evidence to paths whose own finding was executed.

    Only a finding of the same category as the path counts: a verified reentrancy test
    says nothing about an access-control path that happens to share a function.
    """
    by_id = {f.id: f for f in findings}
    for path in paths:
        executed = [by_id[i] for i in path.finding_ids
                    if i in by_id and by_id[i].category == path.category
                    and by_id[i].verification.run is not None]
        if not executed:
            continue
        path.run_ids = [f.verification.run.run_id for f in executed]
        path.evidence_status, path.evidence_note = _path_status(executed[0])
        remediation = executed[0].remediation
        path.patch_status = remediation.status.value if remediation else None


def finding_paths(graph: nx.DiGraph, findings: list[Finding]) -> list[AttackPath]:
    paths = []
    for finding in findings:
        if finding.evidence is None:
            continue
        if finding.detector == "reentrancy-eth":
            paths.append(reentrancy_path(graph, finding, len(paths) + 1))
        elif finding.category == "unchecked-call":
            paths.append(unchecked_call_path(graph, finding, len(paths) + 1))
    return paths

"""Deterministic fallback triage.

Used when no LLM provider is configured. It applies simple, transparent rules to Slither's
evidence so the workbench is fully functional offline. It is labelled `provider="heuristic"`
so the UI never presents it as model reasoning.
"""

from slither.tools.workbench.models import Assessment, Exploitability, Finding
from slither.tools.workbench.verification.templates import ESCALATION_DETECTOR


def _reentrancy(finding: Finding) -> Assessment:
    ev = finding.evidence
    controlled = any("msg.sender" in c for c in ev.low_level_calls + ev.external_calls)
    written = ", ".join(ev.state_written) or "state"
    return Assessment(
        classification=Exploitability.LIKELY if controlled else Exploitability.POSSIBLE,
        confidence=80 if controlled else 55,
        summary=f"External call in {ev.signature} precedes the update of {written}.",
        why_it_matters="Funds or accounting state can be manipulated by re-entering the "
        "function before it finishes.",
        preconditions=[
            "Attacker can make the recipient a contract with a fallback/receive function",
            f"{ev.signature} is callable during the callback",
            "The external call transfers control before state is written",
        ],
        evidence=[f"External call: {c}" for c in ev.low_level_calls + ev.external_calls]
        + [f"State written after call: {w}" for w in ev.state_written],
        impact="Repeated re-entry may drain balances or corrupt accounting.",
        remediation="Apply the checks-effects-interactions pattern or a reentrancy guard.",
        attack_steps=[
            f"Attacker contract calls {ev.signature}",
            "Contract performs the external call to the attacker",
            f"Attacker fallback re-enters {ev.signature}",
            f"{written} is still stale, so the check passes again",
        ],
        affected_state=ev.state_written,
        provider="heuristic",
        model="rules-v1",
    )


def _unchecked_call(finding: Finding) -> Assessment:
    ev = finding.evidence
    return Assessment(
        classification=Exploitability.POSSIBLE,
        confidence=50,
        summary=f"Return value of a low-level call in {ev.signature} is ignored.",
        why_it_matters="A failed transfer is treated as success, so the contract's state "
        "diverges from what actually happened on-chain.",
        preconditions=["The callee can fail or revert", "Caller relies on the call succeeding"],
        evidence=[f"Unchecked call: {c}" for c in ev.low_level_calls],
        false_positive_indicators=[]
        if ev.low_level_calls
        else ["No low-level call resolved in evidence"],
        impact="Silent failures can strand funds or leave accounting inconsistent.",
        remediation="Check the boolean return value and revert on failure, or use a safe wrapper.",
        attack_steps=[
            f"Trigger {ev.signature} with a callee that reverts",
            "Call returns false but execution continues",
        ],
        provider="heuristic",
        model="rules-v1",
    )


def _access_control(finding: Finding) -> Assessment:
    ev = finding.evidence
    unprotected = not ev.is_protected and ev.visibility in ("public", "external")
    return Assessment(
        classification=Exploitability.LIKELY if unprotected else Exploitability.POSSIBLE,
        confidence=75 if unprotected else 45,
        summary=f"{ev.signature} performs a privileged action without a robust caller check.",
        why_it_matters="An attacker may invoke sensitive functionality reserved for the owner.",
        preconditions=["Function is externally reachable", "No effective msg.sender restriction"],
        evidence=[f"Visibility: {ev.visibility}", f"is_protected: {ev.is_protected}"]
        + [f"Writes: {w}" for w in ev.state_written],
        impact="Unauthorized state changes, fund transfer, or contract destruction.",
        remediation="Restrict the function with an access-control modifier or explicit check.",
        attack_steps=[f"Attacker calls {ev.signature} directly"],
        affected_state=ev.state_written,
        provider="heuristic",
        model="rules-v1",
    )


def _privilege_escalation(finding: Finding) -> Assessment:
    ev = finding.evidence
    guard = next((r.label for r in finding.related if r.role == "guard_variable"), "the role")
    privileged = next(
        (r.label for r in finding.related if r.role == "privileged_function"), "privileged code"
    )
    return Assessment(
        classification=Exploitability.LIKELY,
        confidence=75,
        summary=f"{ev.signature} lets any caller overwrite `{guard}`, which gates {privileged}.",
        why_it_matters="An attacker can make themselves the privileged role and then use "
        "every function that role protects.",
        preconditions=[
            f"{ev.signature} is externally callable without a msg.sender check",
            f"{privileged} authorizes callers by comparing msg.sender with `{guard}`",
        ],
        evidence=[f"Writes: {w}" for w in ev.state_written] + [f"is_protected: {ev.is_protected}"],
        impact=f"Unauthorized use of {privileged}.",
        remediation=f"Restrict {ev.signature} to the current `{guard}` (or an admin role).",
        attack_steps=[
            f"Attacker calls {ev.signature} with their own address",
            f"`{guard}` now equals the attacker",
            f"Attacker calls {privileged} and passes the msg.sender check",
        ],
        affected_state=ev.state_written,
        provider="heuristic",
        model="rules-v1",
    )


def _generic(finding: Finding) -> Assessment:
    return Assessment(
        classification=Exploitability.UNKNOWN,
        confidence=30,
        summary=finding.title,
        why_it_matters=finding.wiki_description[:280],
        evidence=[finding.location.label] if finding.location else [],
        impact="See detector documentation.",
        remediation=finding.wiki_recommendation,
        provider="heuristic",
        model="rules-v1",
    )


def heuristic_assess(finding: Finding) -> Assessment:
    if finding.evidence is None:
        return _generic(finding)
    if finding.detector == ESCALATION_DETECTOR:
        return _privilege_escalation(finding)
    if finding.category == "reentrancy":
        return _reentrancy(finding)
    if finding.category == "unchecked-call":
        return _unchecked_call(finding)
    if finding.category == "access-control" or finding.detector in {"suicidal", "missing-zero-check"}:
        return _access_control(finding)
    return _generic(finding)

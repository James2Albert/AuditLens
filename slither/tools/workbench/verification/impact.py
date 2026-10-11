"""Turn values logged by an executed test into impact measurements.

Only values the test actually emitted are used. If a required value is missing, the
measurement is omitted rather than estimated.
"""

from slither.tools.workbench.models import ImpactMeasurement

WEI_PER_ETH = 10**18


def _eth(wei: int) -> str:
    if wei and abs(wei) < 10**12:
        return f"{wei} wei"
    return f"{wei / WEI_PER_ETH:g} ETH"


def _ints(observations: dict[str, str], *keys: str) -> list[int] | None:
    try:
        return [int(observations[k]) for k in keys]
    except (KeyError, ValueError):
        return None


def _reentrancy_impact(obs: dict[str, str]) -> list[ImpactMeasurement]:
    measurements = []
    contract = _ints(obs, "contract_balance_before", "contract_balance_after")
    if contract:
        before, after = contract
        measurements.append(
            ImpactMeasurement(
                key="contract_balance",
                label="Target contract ETH balance",
                before=_eth(before),
                after=_eth(after),
                delta=_eth(after - before),
                unit="ETH",
            )
        )
    attacker = _ints(obs, "attacker_balance_before", "attacker_balance_after")
    if attacker:
        before, after = attacker
        measurements.append(
            ImpactMeasurement(
                key="attacker_balance",
                label="Attacker contract ETH balance (includes the 1 ETH it deposited)",
                before=_eth(before),
                after=_eth(after),
                delta=_eth(after - before),
                unit="ETH",
            )
        )
    solvency = _ints(obs, "victim_deposit_wei", "contract_balance_after")
    if solvency:
        owed, held = solvency
        measurements.append(
            ImpactMeasurement(
                key="solvency_invariant",
                label="Invariant: contract holds at least the honest depositor's un-withdrawn deposit",
                before=f"owed {_eth(owed)}",
                after=f"held {_eth(held)}",
                delta=f"shortfall {_eth(max(0, owed - held))}",
                violated=held < owed,
                unit="ETH",
            )
        )
    reentry = _ints(obs, "reentry_attempts", "reentry_successes")
    if reentry:
        attempts, successes = reentry
        measurements.append(
            ImpactMeasurement(
                key="reentry",
                label="Re-entrant calls into the target (successful / attempted)",
                after=f"{successes} / {attempts}",
                unit="calls",
            )
        )
    return measurements


def _access_control_impact(obs: dict[str, str]) -> list[ImpactMeasurement]:
    succeeded = _ints(obs, "unauthorized_call_succeeded")
    if not succeeded:
        return []
    return [
        ImpactMeasurement(
            key="unauthorized_call",
            label="Privileged call by an arbitrary address completed",
            after="yes" if succeeded[0] else "no",
            unit="",
            violated=bool(succeeded[0]),
        )
    ]


def _balance(obs: dict[str, str], who: str, label: str) -> list[ImpactMeasurement]:
    values = _ints(obs, f"{who}_balance_before", f"{who}_balance_after")
    if not values:
        return []
    before, after = values
    return [
        ImpactMeasurement(
            key=f"{who}_balance",
            label=label,
            before=_eth(before),
            after=_eth(after),
            delta=_eth(after - before),
            unit="ETH",
        )
    ]


def _escalation_impact(obs: dict[str, str]) -> list[ImpactMeasurement]:
    access = _ints(obs, "privileged_call_before_escalation", "privileged_call_after_escalation")
    measurements = []
    if access:
        before, after = access
        measurements.append(
            ImpactMeasurement(
                key="privileged_access",
                label="Access control: attacker's privileged call (same arguments)",
                before="reverted" if before == 0 else "succeeded",
                after="succeeded" if after else "reverted",
                delta="privilege acquired" if after and not before else "no change",
                violated=bool(after and not before),
            )
        )
    escalated = _ints(obs, "escalation_call_succeeded")
    if escalated:
        measurements.append(
            ImpactMeasurement(
                key="role_write",
                label="Attacker's call to the unprotected writer",
                after="succeeded" if escalated[0] else "reverted",
            )
        )
    measurements += _balance(obs, "contract", "Target contract ETH balance (5 ETH fixture)")
    measurements += _balance(obs, "attacker", "Attacker EOA ETH balance")
    return measurements


IMPACT_BUILDERS = {
    "privilege-escalation": _escalation_impact,
    "reentrancy": _reentrancy_impact,
    "access-control": _access_control_impact,
}


def measure(template_name: str, observations: dict[str, str]) -> list[ImpactMeasurement]:
    builder = IMPACT_BUILDERS.get(template_name)
    return builder(observations) if builder else []

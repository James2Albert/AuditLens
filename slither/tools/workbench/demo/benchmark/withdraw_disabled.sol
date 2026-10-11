// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately bad "fix" for VulnerableBank.sol (benchmark control): it blocks the
// reentrancy exploit by making withdraw() always revert, which breaks legitimate use.
// Patch validation must report this as FAILED, not as a successful fix.
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    address payable public feeRecipient;

    constructor() {
        owner = msg.sender;
        feeRecipient = payable(msg.sender);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        revert("withdrawals paused");
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function payFee(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        feeRecipient.call{value: amount}("");
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately vulnerable contract used to demonstrate the Slither Workbench.
// Do not deploy.
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

    // Reentrancy: the external call happens before the balance is cleared.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    // Access control: anyone can take ownership.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // Unchecked low-level call: the return value is ignored.
    function payFee(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        feeRecipient.call{value: amount}("");
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Hand-written corrected counterpart of VulnerableBank.sol (benchmark negative control).
// Keeps the contract name so the same generated tests apply unchanged.
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
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }

    function payFee(uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = feeRecipient.call{value: amount}("");
        require(ok, "fee transfer failed");
    }

    function sweep() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}

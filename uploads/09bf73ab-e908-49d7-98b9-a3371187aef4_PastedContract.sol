// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessControlTest {
    address public owner;
    address public treasury;

    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
        treasury = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: anyone can change the owner.
    function changeOwner(address newOwner) external {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // VULNERABILITY: anyone can redirect the treasury.
    function changeTreasury(address newTreasury) external {
        require(newTreasury != address(0), "Zero address");
        treasury = newTreasury;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(treasury).transfer(amount);
    }

    receive() external payable {}
}
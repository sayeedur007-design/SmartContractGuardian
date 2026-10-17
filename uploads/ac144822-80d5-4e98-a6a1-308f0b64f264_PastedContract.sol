// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyTestV3 {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "Invalid amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // INTENTIONALLY VULNERABLE:
        // External call occurs before updating the balance.
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}
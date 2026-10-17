// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public prizePool;
    uint256 private seed;

    constructor() {
        owner = msg.sender;
        seed = block.timestamp;
    }

    // Vulnerability 1: Reentrancy
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call before updating balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // Vulnerability 2: Missing access control
    function changeOwner(address newOwner) external {
        owner = newOwner;
    }

    // Vulnerability 3: Unchecked access control on prize withdrawal
    function withdrawPrize(address payable recipient) external {
        uint256 amount = prizePool;
        prizePool = 0;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // Vulnerability 4: Weak randomness
    function guessNumber(uint256 guess) external payable {
        require(msg.value == 1 ether, "Pay exactly 1 ETH");

        uint256 randomNumber = uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    msg.sender,
                    seed
                )
            )
        ) % 10;

        if (guess == randomNumber) {
            prizePool += msg.value * 2;
        } else {
            prizePool += msg.value;
        }
    }

    // Vulnerability 5: Unchecked business authorization
    function emergencyWithdraw(address payable recipient) external {
        uint256 amount = address(this).balance;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // Vulnerability 6: Dangerous tx.origin authentication
    function ownerOnlyAction() external view returns (bool) {
        return tx.origin == owner;
    }
}
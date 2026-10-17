```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VLDTestBench {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public prizePool;

    uint256 private secretNumber = 42;

    constructor() payable {
        owner = msg.sender;
        prizePool = msg.value;
    }

    // VULNERABILITY 1: Missing access control
    function changeOwnerVulnerable(address newOwner) external {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // SECURE COMPARISON
    function changeOwnerSecure(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // Deposit ETH into the caller's balance
    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY 2: External call before state update
    function withdrawVulnerable(uint256 amount) external {
        require(amount > 0, "Zero amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // SECURE COMPARISON: Checks-effects-interactions
    function withdrawSecure(uint256 amount) external {
        require(amount > 0, "Zero amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }

    // VULNERABILITY 3: Missing access control on emergency withdrawal
    function emergencyWithdrawVulnerable(
        address payable recipient
    ) external {
        require(recipient != address(0), "Zero recipient");

        uint256 amount = address(this).balance;
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // VULNERABILITY 4: Predictable randomness
    function guessNumber(uint256 guess) external payable {
        require(msg.value == 1 ether, "Pay exactly 1 ETH");

        uint256 randomNumber = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao))
        ) % 100;

        if (guess == randomNumber) {
            (bool success, ) = payable(msg.sender).call{
                value: address(this).balance
            }("");
            require(success, "Prize transfer failed");
        }
    }

    // VULNERABILITY 5: tx.origin authentication
    function txOriginAuthentication() external view returns (bool) {
        return tx.origin == owner;
    }

    // VULNERABILITY 6: Unprotected prize withdrawal
    function withdrawPrizeVulnerable(
        address payable recipient
    ) external {
        require(recipient != address(0), "Zero recipient");

        uint256 amount = prizePool;
        prizePool = 0;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Prize transfer failed");
    }

    receive() external payable {}
}
```
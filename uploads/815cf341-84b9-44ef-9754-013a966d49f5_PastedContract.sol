// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VLDTestBench {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public prizePool;

    constructor() {
        owner = msg.sender;
    }

    // TEST 1: Missing access control
    function changeOwnerVulnerable(address newOwner) external {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // TEST 2: Proper access control
    function changeOwnerSecure(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // TEST 3: Reentrancy vulnerability
    function withdrawVulnerable(uint256 amount) external {
        require(amount > 0, "Zero amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
    }

    // TEST 4: Checks-effects-interactions comparison
    function withdrawSecure(uint256 amount) external {
        require(amount > 0, "Zero amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // TEST 5: Unauthorized contract fund withdrawal
    function emergencyWithdrawVulnerable(
        address payable recipient
    ) external {
        require(recipient != address(0), "Zero recipient");

        uint256 amount = address(this).balance;
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // TEST 6: Owner-restricted fund withdrawal
    function emergencyWithdrawSecure(
        address payable recipient
    ) external {
        require(msg.sender == owner, "Not owner");
        require(recipient != address(0), "Zero recipient");

        uint256 amount = address(this).balance;
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // TEST 7: Predictable block-derived randomness
    function guessNumber(uint256 guess) external payable {
        require(msg.value == 1 ether, "Pay exactly 1 ETH");

        uint256 result = uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    msg.sender
                )
            )
        ) % 10;

        if (guess == result) {
            prizePool += msg.value * 2;
        } else {
            prizePool += msg.value;
        }
    }

    // TEST 8: tx.origin authentication
    function txOriginAuthentication() external view returns (bool) {
        return tx.origin == owner;
    }

    // TEST 9: Unprotected prize withdrawal
    function withdrawPrizeVulnerable(
        address payable recipient
    ) external {
        require(recipient != address(0), "Zero recipient");

        uint256 amount = prizePool;
        prizePool = 0;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
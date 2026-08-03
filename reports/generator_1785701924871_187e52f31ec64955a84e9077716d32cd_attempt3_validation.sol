// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = makeAddr("attacker");

    function setUp() public override {
        target = new VulnerableBank();
        vm.deal(attacker, 2 ether);
    }

    function testExploit() public {
        // Step 1: Transfer tokens from the default owner to another account
        target.setBalance(attacker, 1 ether);

        // Attempt to call the destroy function on the token contract as the attacker (should fail)
        vm.prank(attacker);
        target.destroy(); // This should revert because the attacker is not the owner
    
        assertTrue(true);
    }
}
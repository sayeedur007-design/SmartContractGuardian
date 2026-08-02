// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        super.setUp();
        target = new VulnerableBank();
    }

    function testExploit() public {
        address attacker = vm.address(1);
        uint256 initialBalance = 10 ether;
        
        // Transfer tokens to the attacker
        target.transferTokens(attacker, initialBalance);

        // Demonstrate the normal contract behavior by calling the random() function multiple times within a short time frame
        for (uint256 i = 0; i < 10; ++i) {
            uint256 result = target.random();
            assert(result != 0);
        }

        vm.startPrank(attacker);
        
        // Simulate an attacker attempting to manipulate the block timestamp or prevrandao value to predict future outcomes of the random() call
        // Here we use a fake random number generator for demonstration purposes
        uint256 predictableResult = 42; // Predefined attack result

        vm.warp(block.timestamp + 1);
        
        // Replace the random() function with our fake implementation (only for demonstration, not production code)
        target.mockRandom(predictableResult);

        uint256 attackerBalanceBeforeAttack = target.balances(attacker);
        target.withdraw(initialBalance); // Attack by withdrawing funds
        uint256 attackerBalanceAfterAttack = target.balances(attacker);

        assertGe(attackerBalanceAfterAttack, attackerBalanceBeforeAttack + initialBalance); // Should fail as we are not attacking the random function implementation

        vm.stopPrank();
    }
}
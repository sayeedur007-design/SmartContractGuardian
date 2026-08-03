// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address victim = deployer;
    address attacker = user;

    function setUp() public override {
        vm.startPrank(deployer);
        target = new VulnerableBank();
        vm.stopPrank();
    }

    function testExploit() public {
        uint256 exploitValue = 1 ether;
        
        // Step 1: Victim (deployer) deposits ETH into the contract
        victim.deposit{value: exploitValue}();

        // Step 2: Call the unsafeSend function with insufficient funds to observe the failure
        bytes memory callData = abi.encodeWithSignature("unsafeSend(address,uint256)", attacker, exploitValue);
        
        vm.expectRevert(bytes4(keccak256("Error: Insufficient balance"))); // Expect a revert because the internal ETH transfer might fail due to insufficient balance in the `unsafeTransferETHInternal` function
       (vm.prank(victim); target.unsafeSend(attacker, exploitValue);

        // Step 3: Verify that the attacker did not receive any funds
        uint256 attackerBalanceBefore = attacker.balance;
        assertEq(attackerBalanceBefore, balanceOf(attacker));
        
        // Log the balances for verification
        balanceLog(victim, "Victim Balance Before Attack");
        balanceLog(attacker, "Attacker Balance Before Attack");
        balanceLog(address(target), "Target Contract Balance Before Attack");

        uint256 attackerBalanceAfter = attacker.balance;
        assertEq(attackerBalanceAfter, balanceOf(attacker));
        
        // Log the balances for verification
        balanceLog(victim, "Victim Balance After Attack");
        balanceLog(attacker, "Attacker Balance After Attack");
        balanceLog(address(target), "Target Contract Balance After Attack");
    }
}
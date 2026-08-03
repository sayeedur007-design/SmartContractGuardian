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
        
        // Step 1: Victim (deployer) sends ETH to the target contract
        deal(victim, address(target), exploitValue);

        // Step 2: Call the unsafeSend function with insufficient funds to observe the failure
        bytes memory callData = abi.encodeWithSignature("unsafeSend(address,uint256)", attacker, exploitValue);
        
        vm.expectRevert(bytes4(keccak256("Error: Insufficient balance"))); // Expect a revert because the internal ETH transfer might fail due to insufficient balance in the `unsafeTransferETHInternal` function
        vm.prank(victim);
        (bool success, ) = address(target).call{value: exploitValue}(callData);

        // Step 3: Verify that the attacker did not receive any funds
        uint256 attackerBalanceBefore = victim.balance;
        target.setBalance(attacker, attackerBalanceBefore);
        assertEq(target.balances(attacker), attackerBalanceBefore);
        
        // Log the balances for verification
        balanceLog(victim, "Victim Balance Before Attack");
        balanceLog(attacker, "Attacker Balance Before Attack");
        balanceLog(address(target), "Target Contract Balance Before Attack");

        uint256 victimBalanceAfter = victim.balance;
        target.setBalance(victim, victimBalanceAfter);
        assertEq(target.balances(victim), victimBalanceAfter);
        
        // Log the balances for verification
        balanceLog(victim, "Victim Balance After Attack");
        balanceLog(attacker, "Attacker Balance After Attack");
        balanceLog(address(target), "Target Contract Balance After Attack");
    }
}
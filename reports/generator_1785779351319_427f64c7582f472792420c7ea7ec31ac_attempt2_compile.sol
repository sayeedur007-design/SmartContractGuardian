// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract TestOwnershipBug is BaseTestWithBalanceLog {
    OwnershipBug target;

    function setUp() public {
        owner = vm.addr(1); // Assuming owner has address 1 for the purposes of testing
        target = new OwnershipBug(owner);
    }

    function testExploit() public balanceLog {
        // Step 1: Deploy a single contract with the vulnerable `destroy()` function
        // This is already done in setUp

        // Step 2: Transfer some Ether to this contract from your student account
        vm.deal(address(target), 1 ether);

        // Step 3: Call the `destroy()` function from the owner's account
        vm.prank(owner);
        target.destroy();

        // Validation (Step 1)
        assertEq(address(target).balance, 0, "Funds were not destroyed");

        // Add balance for validation (Step 2)
        balanceLog.push(address(this), "Initial Balance", address(this).balance);
        balanceLog.push(address(this), "After Exploit Balance", address(this).balance);

        // Assert that the owner's balance has increased
        assertGt(owner.balance, 0, "Owner did not receive any funds");
    }
}
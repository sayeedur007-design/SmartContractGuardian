// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract TestOwnershipBug is BaseTestWithBalanceLog {
    OwnershipBug target;

    function setUp() public {
        super.setUp();
        target = new OwnershipBug();
    }

    function testExploit() public balanceLog {
        // Set attacker as owner to demonstrate the vulnerability
        vm.prank(owner);
        target.transferOwnership(attacker);

        // Ensure the attacker can call destroy function without revert
        vm.prank(attacker);
        target.destroy();

        // Verify that the contract self-destructed
        assertEq(address(target).balance, 0);
    }
}
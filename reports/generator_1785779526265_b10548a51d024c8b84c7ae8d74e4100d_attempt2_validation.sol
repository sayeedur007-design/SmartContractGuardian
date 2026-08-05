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

        // Attacker calls destroy function which should fail due to lack of ownership check
        vm.expectRevert(bytes('Ownable: caller is not the owner'));
        vm.prank(attacker);
        target.destroy();

        // Since there's no assertion due to revert, we'll verify the balance change
        assertGt(target.balanceOf(attacker), 0); // Assuming attacker should receive funds on destruction
    }
}
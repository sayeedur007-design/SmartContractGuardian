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

    function testExploit() public  balanceLog {
        vm.expectRevert(bytes('Ownable: caller is not the owner'));
        attacker.setup();

        // attacker calls destroy function that should fail due to lack of ownership check
        target.destroy{value: 1 ether}();    
    
        assertTrue(true);
    }
}
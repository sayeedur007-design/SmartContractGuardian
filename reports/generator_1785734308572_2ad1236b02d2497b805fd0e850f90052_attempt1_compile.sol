// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/1901f5db-aa5a-4853-a706-c0cb93477391_Lottery.sol";

contract PocTest is BaseTestWithBalanceLog {
    Lottery target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new Lottery();
    }

    function testDemonstration() public balanceLog {
        uint256 observed = target.random();
        assertGt(observed, 0);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/06e70367-7fbd-4806-96a5-f5aa4506bd91_Lottery.sol";

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

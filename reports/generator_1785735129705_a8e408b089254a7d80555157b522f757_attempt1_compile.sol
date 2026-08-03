// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/b37a5567-4c0e-4323-b705-44bd0e529b62_Lottery.sol";

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

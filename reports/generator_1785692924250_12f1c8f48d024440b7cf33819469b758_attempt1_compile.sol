// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/22e13570-5b8b-4107-9839-d5330d99d0bb_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
    }

    function testExploit() public balanceLog {
        target.destroy();
        assertEq(address(target).balance, 0);
    }
}

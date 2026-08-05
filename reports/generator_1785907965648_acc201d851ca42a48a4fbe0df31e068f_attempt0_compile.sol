// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/5684f35b-181f-4225-ac36-a9189f9c2961_Mixed.sol";

contract PocTest is BaseTestWithBalanceLog {
    MixedTest target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new MixedTest();
    }

    function testExploit() public balanceLog {
        target.destroy();
        assertEq(address(target).balance, 0);
    }
}

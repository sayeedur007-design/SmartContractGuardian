// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract ExploitTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Step 1: Demonstrate normal behavior
        uint256 initialBalance = target.balances(attacker);
        assertEq(initialBalance, 0);

        target.deposit{value: 1 ether}();
        uint256 depositedBalance = target.balances(attacker);
        assertEq(depositedBalance, 1 ether);

        // Step 2: Manipulate block timestamp
        vm.warp(1672531200); // Set timestamp to Jan 1, 2023

        // Manipulation step
        target.deposit{value: 1 ether}();

        // Verify that the balance has not changed due to time manipulation
        uint256 manipulatedBalance = target.balances(attacker);
        assertEq(manipulatedBalance, depositedBalance);

        // Step 3: Demonstrate random() output consistency
        uint256 initialRandomValue = target.random();
        vm.warp(1672531201); // Set timestamp to Jan 1, 2023, +1 second
        uint256 subsequentRandomValue = target.random();

        assertEq(initialRandomValue, subsequentRandomValue);

        // Step 4: Demonstrate exploitation (if applicable)
        vm.prank(attacker);
        bytes memory payload = "exploit";
        target.unsafeSend(address(0x1), 0.1 ether);
    }
}
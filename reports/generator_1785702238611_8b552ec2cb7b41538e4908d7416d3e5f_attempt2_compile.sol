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
        target.transferOwnership(address(0));

        assertEq(target.owner(), address(0), "Owner should be the zero-address");
        balanceLog.logBalances("Balances after exploit", address(this), address(target));
    }
}
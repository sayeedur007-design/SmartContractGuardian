// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public virtual override {
        super.setUp();
        target = new VulnerableBank();
    }

    function testExploit() external  balanceLog {
        vm.prank(attacker);
        // Setup the victim account with some balance
        address attacker = getForkUser(0);
        hoax(attacker, ether(1));
        vm.deal(attacker, ether(1));

        // The victim deposits Ether into the contract
        target.deposit{value: ether(1)}();

        // The attacker attempts to exploit the vulnerability by using low-level call with insufficient gas
        address vulnerableBankAddress = address(target);
        bytes memory payload = abi.encodeWithSelector(VulnerableBank.withdraw.selector, ether(1));
        vm.expectRevert("low-level call failed");
        (bool success,) = vulnerableBankAddress.call{gas: 200}(payload);

        // The attacker's withdrawal failed due to insufficient gas in the low-level call
        assertGt(target.balances(attacker), 0); // Attacker's balance should still be positive
    }
}
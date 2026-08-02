// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract Re entringReceiver is VulnerableBank {
    address public receiverAddress;
    
    constructor(address _receiverAddress) {
        receiverAddress = _receiverAddress;
    }
    
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");
        
        // Simulate re-entering by calling the withdrawal again
        if (msg.sender == receiverAddress) {
            revert("Re-entrancy detected");
        }
        
        payable(msg.sender).transfer(balance);
        balances[msg.sender] = 0;
    }
}

contract ExploitTest is BaseTestWithBalanceLog {
    
    VulnerableBank target;
    Re entringReceiver reenterer;

    function setUp() public override {
        super.setUp();
        target = new VulnerableBank();

        vm.deal(address(target), 1 ether);
        
        // Deploy the re-entrancing receiver
        reenterer = new Re entringReceiver(address(target));

        // Transfer initial funds to the re-entracing receiver
        target.setBalance(address(reenterer), 0.5 ether);  
    }

    function testExploit() public {
        vm.prank(address(reenterer));
        
        // Deposit through the re-entering receiver
        target.deposit{value: 1 ether}();
        
        // Trigger the withdraw function to cause a re-entrancy
        uint256 initialBalance = reenterer.balance;
        reenterer.withdraw();  
        
        // Assert that the re-entrancing receiver has withdrawn more than its original deposit
        assertGt(reenterer.balance, initialBalance + 0.1 ether);   
    }
}
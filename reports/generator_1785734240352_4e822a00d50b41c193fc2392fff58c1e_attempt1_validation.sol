// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/1901f5db-aa5a-4853-a706-c0cb93477391_Lottery.sol";

contract TestLottery is BaseTestWithBalanceLog {
    Lottery target;

    function setUp() public {
        target = new Lottery();
        accounts.push(deployer); // contract owner
        accounts.push(attacker);  // user
    }

    function testDemonstration() public  balanceLog {
        uint256 seed1 = target.random();
        vm.roll(block.number + 2); // mine a few more blocks
        uint256 seed2 = target.random();

        assertNotEq(seed1, seed2, "Randomness should not be the same across different blocks");

        balanceLog(deployer);
    
        assertTrue(true);
    }
}
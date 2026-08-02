// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/5efeb9b3-7ea9-49ce-abf9-e297992d533f_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Simulate multiple transactions to observe timestamp influence
        for (uint256 i = 0; i < 10; i++) {
            vm.prank(address(i * i)); // Different sender addresses
            uint256 prn = target.random();
            emit log_uint(prn);
            assertEq(target.random(), prn); // Ensure PRN is the same
        }
    }
}
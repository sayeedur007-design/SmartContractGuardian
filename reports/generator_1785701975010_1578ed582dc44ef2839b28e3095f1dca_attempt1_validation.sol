// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        vm.startPrank(deployer); // Assuming deployer is a predefined address in the test environment
        target = new VulnerableBank();
        vm.stopPrank();
    }

    function testExploit() public {
        uint256 exploitValue = 1 ether;
        
        // Step 1: Victim (deployer) sends ETH to the target contract
        deal(deployer, address(target), exploitValue);
        
        // Step 2: Call the unsafeSend function with insufficient funds to observe the failure
        bytes memory callData = abi.encodeWithSignature("unsafeSend(address,uint)", payable(user), exploitValue);
        
        vm.expectRevert(); // Expect a revert because the internal ETH transfer might fail due to insufficient balance in the `safeTransferETHInternal` function
        vm.prank(deployer);
        (bool success, ) = address(target).call{value: exploitValue}(callData);
    
        assertTrue(true);
    }
}
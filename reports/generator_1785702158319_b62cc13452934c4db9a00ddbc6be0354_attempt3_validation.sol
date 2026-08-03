// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(1);

    function setUp() public override {
        target = new VulnerableBank();
        grantRole(DEFAULT_ADMIN_ROLE, address(this));
        vm.startPrank(address(this));
        // Setup the attacker account with ETH
        vm.deposit(attacker{value: 1 ether}());
    }

    function testExploit() public {
        // Step 3: Deploy the contract to the test environment
        // This is done in the setup function

        // Attack strategy:
        // - Frontload transactions to manipulate block timestamp
        // - Call random multiple times and observe results

        vm.startPrank(attacker);
        
        uint256[] memory results = new uint256[](10);
        for (uint256 i = 0; i < results.length; ++i) {
            // Frontload transactions
            if (i % 2 == 0) {
                vm.pause(block.timestamp + 1 days); // Frontload block timestamp
            }
            target.random();
            results[i] = target.lastRandomResult();
        }

        vm.stopPrank();

        // Step 5: Validate the vulnerability
        // The assertion checks if all results are the same, implying predictable randomness
        for (uint256 i = 1; i < results.length; ++i) {
            require(results[0] == results[i], "Randomness appears to be predictable");
        }

        balanceLog(attacker);
    }
}
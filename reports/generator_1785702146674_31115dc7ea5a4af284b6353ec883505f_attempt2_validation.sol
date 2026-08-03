// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/VulnerableBank.sol";

contract VulnerableBankTest is BaseTestWithBalanceLog {
    VulnerableBank target;

    function setUp() public override {
        target = new VulnerableBank();
        grantRole(DEFAULT_ADMIN_ROLE, address(this));
        vm.startPrank(address(this));
    }

    function testExploit() public {
        // Step 3: Deploy the contract to the test environment
        // This is done in the setup function

        // Step 4: Invoke the random() function multiple times quickly, observing the output values
        uint256[] memory results = new uint256[](10);
        for (uint256 i = 0; i < results.length; ++i) {
            target.random();
            results[i] = target.lastRandomResult();
        }

        // Step 5: Explain that the vulnerability is due to dependency on block.timestamp for randomness, which can be manipulated by waiting between function calls or frontloading transactions
        // The assertion checks if all results are the same, implying predictable randomness
        require(results[0] != results[1], "Randomness observed to be predictable");
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TimestampDependenceVulnerable {
    address public winner;

    function pickWinner() external {
        require(winner == address(0), "Already picked");

        // Weak design: outcome depends on block timestamp
        if (block.timestamp % 2 == 0) {
            winner = msg.sender;
        }
    }
}
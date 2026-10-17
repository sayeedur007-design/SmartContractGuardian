// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnprotectedAdmin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address newOwner) external {
        // Vulnerability: no access-control check.
        owner = newOwner;
    }
}
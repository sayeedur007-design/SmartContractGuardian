// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdrawAll(address payable recipient) external {
        require(tx.origin == owner, "Not owner");

        (bool ok, ) = recipient.call{value: address(this).balance}("");
        require(ok, "Transfer failed");
    }

    receive() external payable {}
}
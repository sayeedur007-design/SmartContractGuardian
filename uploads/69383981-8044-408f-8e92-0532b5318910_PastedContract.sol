// SPDX-License-Identifier: MIT
 pragma solidity ^0.8.20;

 contract OwnershipBug {
     address public owner;

     constructor() {
         owner = msg.sender;
     }

     // VULNERABILITY 1: Anyone can change the owner.
     function transferOwnership(address newOwner) external {
         owner = newOwner;
     }

     // VULNERABILITY 2: Anyone can trigger selfdestruct.
     function destroy() external {
         selfdestruct(payable(msg.sender));
     }
 }
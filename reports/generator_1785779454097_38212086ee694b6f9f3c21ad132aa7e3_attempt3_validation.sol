// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
import "./basetest.sol";
import "../src/da51b355-8ab8-447c-9497-f80be5933694_OwnershipBug.sol";

contract OwnershipBugTest is BaseTestWithBalanceLog {
    address attacker;
    OwnershipBug target;

    function setUp() public {
        target = new OwnershipBug();
        
        // Deploy the initial owner with some ether
        vm.deal(address(target), 10 ether);
        
        // Assign the contract owner to deployer for now
        target.transferOwnership(msg.sender);

        // Choose an attacker address different from the contract's initial owner
        attacker = address(0xBAD);

        // Deployer has ownership, attacker does not yet
    }

    function testExploit() public balanceLog {
        vm.startPrank(attacker); // Start prank with the attacker's account
        target.transferOwnership(address(0x1234567890123456789012345678901234567890)); // Attempt to change owner
        vm.stopPrank();

        // Validate that the ownership has not changed, should fail due to lack of checks
        assertEq(target.owner(), address(OwnershipBug).creationCode); // Ensure the owner remains unchanged as expected
    }
}
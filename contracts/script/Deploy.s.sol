// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/SecurityRegistry.sol";
import "../src/WatchlistHandler.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        SecurityRegistry securityRegistry = new SecurityRegistry();
        console.log("SecurityRegistry deployed at:", address(securityRegistry));

        WatchlistHandler watchlistHandler = new WatchlistHandler();
        console.log("WatchlistHandler deployed at:", address(watchlistHandler));

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IReverseRegistrar} from "../reverseRegistrar/IReverseRegistrar.sol";

contract MockReverseRegistrar is IReverseRegistrar {
    mapping(address => string) public names;
    function setDefaultResolver(address) external {}
    function setName(string memory name) external returns (bytes32) {
        names[msg.sender] = name;
        return bytes32(0);
    }
    function claim(address) external returns (bytes32) { return bytes32(0); }
    function claimForAddr(address, address, address) external returns (bytes32) { return bytes32(0); }
    function claimWithResolver(address, address) external returns (bytes32) { return bytes32(0); }
    function setNameForAddr(address addr, address, address, string memory name) external returns (bytes32) {
        names[addr] = name;
        return bytes32(0);
    }
    function node(address) external pure returns (bytes32) { return bytes32(0); }
}

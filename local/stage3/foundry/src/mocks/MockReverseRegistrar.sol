// SPDX-License-Identifier: MIT
pragma solidity ~0.8.17;

import {IReverseRegistrar} from "../reverseRegistrar/IReverseRegistrar.sol";
import {IDefaultReverseRegistrar} from "../reverseRegistrar/IDefaultReverseRegistrar.sol";

/**
 * @notice HARNESS DIVERGENCE: stubs for reverse registrars.
 * H2 focuses on the resolver multicallWithNodeCheck reentrancy window during
 * ETHRegistrarController.register; reverse-record side effects are out of scope.
 * Tests set reverseRecord=0 so these stubs are never invoked on the happy path,
 * but the controller constructor still requires the interfaces.
 */
contract MockReverseRegistrar is IReverseRegistrar {
    function setDefaultResolver(address) external pure override {}

    function claim(address) external pure override returns (bytes32) {
        return bytes32(0);
    }

    function claimForAddr(
        address,
        address,
        address
    ) external pure override returns (bytes32) {
        return bytes32(0);
    }

    function claimWithResolver(
        address,
        address
    ) external pure override returns (bytes32) {
        return bytes32(0);
    }

    function setName(string memory) external pure override returns (bytes32) {
        return bytes32(0);
    }

    function setNameForAddr(
        address,
        address,
        address,
        string memory
    ) external pure override returns (bytes32) {
        return bytes32(0);
    }

    function node(address) external pure override returns (bytes32) {
        return bytes32(0);
    }
}

contract MockDefaultReverseRegistrar is IDefaultReverseRegistrar {
    function setName(string memory) external pure override {}

    function setNameForAddrWithSignature(
        address,
        uint256,
        string memory,
        bytes memory
    ) external pure override {}

    function setNameForAddr(address, string memory) external pure override {}
}

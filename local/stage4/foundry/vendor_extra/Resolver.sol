// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;

/**
 * @title Resolver (harness-minimal)
 * @notice HARNESS DIVERGENCE from ens-contracts v1.7.0 `contracts/resolvers/Resolver.sol`:
 *         The production interface aggregates many profile interfaces (ABI/Addr/Text/...).
 *         ETHRegistrarController.register only type-casts the user-supplied resolver and
 *         calls `multicallWithNodeCheck`. This slim interface is sufficient for that
 *         external call while avoiding copying the full PublicResolver dependency tree.
 *         The call encoding / reentrancy surface is identical to production.
 */
interface Resolver {
    function multicallWithNodeCheck(
        bytes32 nodehash,
        bytes[] calldata data
    ) external returns (bytes[] memory results);
}

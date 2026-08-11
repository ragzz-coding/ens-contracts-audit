// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {ENS} from "../registry/ENS.sol";
import {INameWrapper} from "../wrapper/INameWrapper.sol";
import {Multicallable} from "../resolvers/Multicallable.sol";

/**
 * LOCAL HARNESS — authorization + multicall + setAddr only.
 * Mirrors PublicResolver.isAuthorised / multicall / setAddr semantics from
 * ens-contracts v1.7.0 PublicResolver + AddrResolver + ResolverBase.
 * Divergence: omits other record profiles and ReverseClaimer.
 */
contract PublicResolverAuthHarness is Multicallable {
    ENS public immutable ens;
    INameWrapper public immutable nameWrapper;
    address public immutable trustedETHController;
    address public immutable trustedReverseRegistrar;

    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(address => mapping(bytes32 => mapping(address => bool))) private _tokenApprovals;
    mapping(bytes32 => address) private _addrs;

    error Unauthorised();

    constructor(
        ENS _ens,
        INameWrapper wrapperAddress,
        address _trustedETHController,
        address _trustedReverseRegistrar
    ) {
        ens = _ens;
        nameWrapper = wrapperAddress;
        trustedETHController = _trustedETHController;
        trustedReverseRegistrar = _trustedReverseRegistrar;
    }

    function setApprovalForAll(address operator, bool approved) external {
        require(msg.sender != operator, "ERC1155: setting approval status for self");
        _operatorApprovals[msg.sender][operator] = approved;
    }

    function isApprovedForAll(address account, address operator) public view returns (bool) {
        return _operatorApprovals[account][operator];
    }

    function approve(bytes32 node, address delegate, bool approved) external {
        require(msg.sender != delegate, "Setting delegate status for self");
        _tokenApprovals[msg.sender][node][delegate] = approved;
    }

    function isApprovedFor(address owner, bytes32 node, address delegate) public view returns (bool) {
        return _tokenApprovals[owner][node][delegate];
    }

    function isAuthorised(bytes32 node) internal view returns (bool) {
        if (msg.sender == trustedETHController || msg.sender == trustedReverseRegistrar) {
            return true;
        }
        address owner = ens.owner(node);
        if (owner == address(nameWrapper)) {
            owner = nameWrapper.ownerOf(uint256(node));
        }
        return owner == msg.sender || isApprovedForAll(owner, msg.sender)
            || isApprovedFor(owner, node, msg.sender);
    }

    function setAddr(bytes32 node, address a) external {
        if (!isAuthorised(node)) revert Unauthorised();
        _addrs[node] = a;
    }

    function addr(bytes32 node) external view returns (address) {
        return _addrs[node];
    }
}

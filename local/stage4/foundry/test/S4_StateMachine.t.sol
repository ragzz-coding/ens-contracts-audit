// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Test, console2} from "forge-std/Test.sol";
import {ENSRegistry} from "../src/registry/ENSRegistry.sol";
import {BaseRegistrarImplementation} from "../src/ethregistrar/BaseRegistrarImplementation.sol";
import {NameWrapper} from "../src/wrapper/NameWrapper.sol";
import {INameWrapper, CANNOT_UNWRAP, CANNOT_BURN_FUSES, CANNOT_TRANSFER, CANNOT_SET_RESOLVER, CANNOT_CREATE_SUBDOMAIN, CANNOT_APPROVE, PARENT_CANNOT_CONTROL, IS_DOT_ETH, CAN_EXTEND_EXPIRY} from "../src/wrapper/INameWrapper.sol";
import {StaticMetadataService} from "../src/wrapper/StaticMetadataService.sol";
import {IMetadataService} from "../src/wrapper/IMetadataService.sol";
import {PublicResolverAuthHarness as PublicResolver} from "../src/harness/PublicResolverAuthHarness.sol";
import {MockReverseRegistrar} from "../src/mocks/MockReverseRegistrar.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * Stage 4 — NameWrapper / registrar / resolver authorization experiments.
 * Sources under src/ are v1.7.0 copies. Mocks are local-only fixtures.
 *
 * Do NOT reopen H1/H2/H3.
 */
contract S4_NameWrapperStateMachineTest is Test, IERC1155Receiver, IERC721Receiver {
    bytes32 constant ETH_NODE =
        0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae;
    bytes32 constant ETH_LABEL = keccak256("eth");
    bytes32 constant ROOT_NODE = bytes32(0);
    bytes32 constant ADDR_REVERSE_NODE =
        0x91d1777781884d03a6757a803996e38de2a42967fb37eeaca72729271025a9e2;
    bytes32 constant REVERSE_LABEL = keccak256("reverse");
    bytes32 constant ADDR_LABEL = keccak256("addr");

    uint256 constant DURATION = 365 days;
    uint64 constant GRACE = 90 days;

    ENSRegistry ens;
    BaseRegistrarImplementation base;
    NameWrapper wrapper;
    PublicResolver resolver;
    MockReverseRegistrar reverse;
    StaticMetadataService meta;

    address admin = makeAddr("admin");
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");
    address parentOwner = makeAddr("parentOwner");
    address childOwner = makeAddr("childOwner");

    function setUp() public {
        vm.warp(1_700_000_000);
        vm.startPrank(admin);

        ens = new ENSRegistry();
        // Reverse tree for ReverseClaimer constructors
        reverse = new MockReverseRegistrar();
        ens.setSubnodeOwner(ROOT_NODE, REVERSE_LABEL, admin);
        bytes32 reverseNode = keccak256(abi.encodePacked(ROOT_NODE, REVERSE_LABEL));
        ens.setSubnodeOwner(reverseNode, ADDR_LABEL, address(reverse));

        base = new BaseRegistrarImplementation(ens, ETH_NODE);
        ens.setSubnodeOwner(ROOT_NODE, ETH_LABEL, address(base));

        meta = new StaticMetadataService("https://meta.example/");
        wrapper = new NameWrapper(ens, base, IMetadataService(address(meta)));
        // NameWrapper must be registrar controller to registerAndWrap / renew
        base.addController(address(wrapper));
        // Allow wrapETH2LD path: user registers via direct controller mint for tests
        base.addController(admin);

        resolver = new PublicResolver(
            ens,
            wrapper,
            address(0), // no trusted ETH controller in these tests
            address(reverse)
        );

        vm.stopPrank();
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 10 ether);
        vm.deal(parentOwner, 10 ether);
        vm.deal(childOwner, 10 ether);
    }

    // --- helpers ---

    function _labelhash(string memory label) internal pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    function _ethNode(string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ETH_NODE, _labelhash(label)));
    }

    function _dnsEthName(string memory label) internal pure returns (bytes memory) {
        // DNS encode: len + label + 3eth + 0
        bytes memory lb = bytes(label);
        require(lb.length < 256, "label too long");
        return bytes.concat(bytes1(uint8(lb.length)), lb, hex"03657468", hex"00");
    }

    function _registerAndWrap(
        string memory label,
        address to,
        uint16 ownerFuses
    ) internal returns (bytes32 node, uint256 tokenId) {
        tokenId = uint256(_labelhash(label));
        node = _ethNode(label);
        // admin is controller: mint NFT to `to`
        vm.prank(admin);
        base.register(tokenId, to, DURATION);
        // wrap
        vm.startPrank(to);
        base.setApprovalForAll(address(wrapper), true);
        wrapper.wrapETH2LD(label, to, ownerFuses, address(0));
        vm.stopPrank();
    }

    // ERC1155/721 receivers so this test contract can hold tokens if needed
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == type(IERC721Receiver).interfaceId;
    }

    // =========================================================================
    // TARGET 1A — ownership sync after wrap
    // =========================================================================

    function test_S4_1A_wrap_syncsRegistryAndWrapper() public {
        (bytes32 node, uint256 tokenId) = _registerAndWrap("alice", victim, 0);
        assertEq(ens.owner(node), address(wrapper), "registry owner must be wrapper");
        assertEq(wrapper.ownerOf(uint256(node)), victim, "wrapper owner victim");
        assertEq(base.ownerOf(tokenId), address(wrapper), "NFT held by wrapper");
        // attacker cannot take over
        vm.prank(attacker);
        vm.expectRevert();
        wrapper.safeTransferFrom(victim, attacker, uint256(node), 1, "");
    }

    function test_S4_1A_attackerCannotWrapVictimsUnwrappedName() public {
        uint256 tokenId = uint256(_labelhash("bob"));
        bytes32 node = _ethNode("bob");
        vm.prank(admin);
        base.register(tokenId, victim, DURATION);
        // ENS owner is victim via register
        assertEq(base.ownerOf(tokenId), victim);
        vm.prank(attacker);
        vm.expectRevert();
        wrapper.wrapETH2LD("bob", attacker, 0, address(0));
        assertEq(ens.owner(node), victim); // still victim (register sets subnode)
    }

    // =========================================================================
    // TARGET 1B — fuse bypass attempts
    // =========================================================================

    function test_S4_1B_cannotTransfer_enforced() public {
        (bytes32 node,) = _registerAndWrap(
            "locked",
            victim,
            uint16(CANNOT_UNWRAP | CANNOT_TRANSFER)
        );
        // burning CANNOT_TRANSFER requires CU+PCC; wrapETH2LD auto-sets PCC|IS_DOT_ETH
        // Need to burn CU first then transfer fuse — wrap with CU|CANNOT_TRANSFER
        // Re-do with proper fuses: CU is required for other owner fuses
        // Actually wrapETH2LD with ownerControlledFuses including CU|CANNOT_TRANSFER
        // Let's check current fuses
        (, uint32 fuses,) = wrapper.getData(uint256(node));
        console2.log("fuses", fuses);
        // If CANNOT_TRANSFER not set because CU missing, burn properly:
        if (fuses & CANNOT_TRANSFER == 0) {
            vm.prank(victim);
            // must include CU when burning owner fuses
            wrapper.setFuses(node, uint16(CANNOT_UNWRAP | CANNOT_TRANSFER));
        }
        vm.prank(victim);
        vm.expectRevert();
        wrapper.safeTransferFrom(victim, attacker, uint256(node), 1, "");
        assertEq(wrapper.ownerOf(uint256(node)), victim);
    }

    function test_S4_1B_PCC_blocksParentReplace_whileLive() public {
        // parent = .eth 2LD wrapped by parentOwner
        (bytes32 parentNode,) = _registerAndWrap("parent", parentOwner, uint16(CANNOT_UNWRAP));
        // create emancipated child with PCC
        vm.prank(parentOwner);
        bytes32 childNode = wrapper.setSubnodeOwner(
            parentNode,
            "child",
            childOwner,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP,
            type(uint64).max
        );
        assertEq(wrapper.ownerOf(uint256(childNode)), childOwner);
        // parent tries to replace child owner while live+PCC
        vm.prank(parentOwner);
        vm.expectRevert();
        wrapper.setSubnodeOwner(parentNode, "child", attacker, 0, type(uint64).max);
        assertEq(wrapper.ownerOf(uint256(childNode)), childOwner);
    }

    function test_S4_1B_CANNOT_CREATE_SUBDOMAIN_blocksNewChild() public {
        (bytes32 parentNode,) = _registerAndWrap(
            "nosub",
            parentOwner,
            uint16(CANNOT_UNWRAP | CANNOT_CREATE_SUBDOMAIN)
        );
        vm.prank(parentOwner);
        vm.expectRevert();
        wrapper.setSubnodeOwner(parentNode, "x", attacker, 0, type(uint64).max);
    }

    function test_S4_1B_unwrap_blockedBy_CANNOT_UNWRAP() public {
        (bytes32 node,) = _registerAndWrap("nounwrap", victim, uint16(CANNOT_UNWRAP));
        bytes32 labelhash = _labelhash("nounwrap");
        vm.prank(victim);
        vm.expectRevert();
        wrapper.unwrapETH2LD(labelhash, victim, victim);
        assertEq(ens.owner(node), address(wrapper));
    }

    /// @dev Known design: after emancipated child expires, parent can recreate UNLESS
    ///      CANNOT_CREATE_SUBDOMAIN burned on parent. Not a vuln if documented — verify enforcement.
    function test_S4_1B_expiredEmancipatedChild_parentRecreate_requiresNoCCS() public {
        (bytes32 parentNode,) = _registerAndWrap("p2", parentOwner, uint16(CANNOT_UNWRAP));
        uint64 shortExpiry = uint64(block.timestamp + 1 days);
        vm.prank(parentOwner);
        bytes32 childNode = wrapper.setSubnodeOwner(
            parentNode,
            "kid",
            childOwner,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP,
            shortExpiry
        );
        // warp past child expiry (but parent still live)
        vm.warp(uint256(shortExpiry) + 1);
        // child owner view cleared due to PCC+expiry
        assertEq(wrapper.ownerOf(uint256(childNode)), address(0));
        // parent WITHOUT CANNOT_CREATE_SUBDOMAIN can recreate — by design
        vm.prank(parentOwner);
        wrapper.setSubnodeOwner(parentNode, "kid", attacker, 0, type(uint64).max);
        assertEq(wrapper.ownerOf(uint256(childNode)), attacker);
        console2.log("DESIGN: parent recreates expired emancipated child without CCS fuse");
    }

    function test_S4_1B_expiredEmancipatedChild_CCS_blocksRecreate() public {
        (bytes32 parentNode,) = _registerAndWrap(
            "p3",
            parentOwner,
            uint16(CANNOT_UNWRAP | CANNOT_CREATE_SUBDOMAIN)
        );
        uint64 shortExpiry = uint64(block.timestamp + 1 days);
        // Parent already has CCS; creating NEW child when empty should fail...
        // Actually CCS blocks creating new when expired/empty. Creating first child while live:
        // _checkCanCallSetSubnodeOwner: if not expired empty path, checks PCC on child.
        // First create: child doesn't exist — expired&&(owner0||ens0) → check CCS on parent.
        // For brand new child, subnodeExpiry is 0 (< now) and owner 0 → CCS check applies!
        // So parent with CCS cannot create ANY new subdomain.
        vm.prank(parentOwner);
        vm.expectRevert();
        wrapper.setSubnodeOwner(
            parentNode,
            "kid2",
            childOwner,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP,
            shortExpiry
        );
    }

    // =========================================================================
    // TARGET 1C — expiry / unwrap / rewrap / grace
    // =========================================================================

    function test_S4_1C_gracePeriod_blocksModify() public {
        (bytes32 node, uint256 tokenId) = _registerAndWrap("grace", victim, 0);
        uint256 registrarExpiry = base.nameExpires(tokenId);
        // Enter registrar grace: now >= registrarExpiry, still < registrarExpiry+90d
        // Wrapper expiry = registrarExpiry + 90d; _isETH2LDInGracePeriod when expiry-90d < now
        // i.e. when now > registrarExpiry
        vm.warp(registrarExpiry + 1);
        assertTrue(block.timestamp > registrarExpiry);
        assertTrue(block.timestamp <= registrarExpiry + uint256(GRACE));
        // canModifyName should be false → unwrap reverts Unauthorised
        vm.prank(victim);
        vm.expectRevert();
        wrapper.unwrapETH2LD(_labelhash("grace"), victim, victim);
        // ownerOf still victim until wrapper expiry
        assertEq(wrapper.ownerOf(uint256(node)), victim);
    }

    function test_S4_1C_afterWrapperExpiry_PCC_ownerCleared() public {
        (bytes32 node, uint256 tokenId) = _registerAndWrap("exp", victim, uint16(CANNOT_UNWRAP));
        uint256 wrapperExpiry = base.nameExpires(tokenId) + uint256(GRACE);
        vm.warp(wrapperExpiry + 1);
        // PCC is always on .eth 2LD → owner view 0
        assertEq(wrapper.ownerOf(uint256(node)), address(0));
        // attacker cannot transfer from zero
        vm.prank(attacker);
        vm.expectRevert();
        wrapper.safeTransferFrom(victim, attacker, uint256(node), 1, "");
    }

    function test_S4_1C_unwrapRewrap_preservesParentFusesOnRemint() public {
        (bytes32 node,) = _registerAndWrap("rw", victim, 0);
        bytes32 labelhash = _labelhash("rw");
        // unwrap
        vm.startPrank(victim);
        wrapper.unwrapETH2LD(labelhash, victim, victim);
        assertEq(ens.owner(node), victim);
        assertEq(base.ownerOf(uint256(labelhash)), victim);
        // rewrap
        base.setApprovalForAll(address(wrapper), true);
        wrapper.wrapETH2LD("rw", victim, 0, address(0));
        vm.stopPrank();
        (, uint32 fuses,) = wrapper.getData(uint256(node));
        assertTrue(fuses & PARENT_CANNOT_CONTROL != 0);
        assertTrue(fuses & IS_DOT_ETH != 0);
        assertEq(wrapper.ownerOf(uint256(node)), victim);
    }

    function test_S4_1C_staleERC1155Approval_clearedOnTransferUnlessCANNOT_APPROVE() public {
        (bytes32 node,) = _registerAndWrap("appr", victim, 0);
        vm.prank(victim);
        wrapper.approve(attacker, uint256(node));
        assertEq(wrapper.getApproved(uint256(node)), attacker);
        // transfer to new owner clears approval (CANNOT_APPROVE not burned)
        vm.prank(victim);
        wrapper.safeTransferFrom(victim, childOwner, uint256(node), 1, "");
        assertEq(wrapper.getApproved(uint256(node)), address(0));
        // attacker cannot extend via stale approval
        // (extendExpiry on .eth 2LD uses parent ETH_NODE — skip; check transfer attempt)
        vm.prank(attacker);
        vm.expectRevert();
        wrapper.safeTransferFrom(childOwner, attacker, uint256(node), 1, "");
    }

    // =========================================================================
    // TARGET 2 — registrar lifecycle divergence
    // =========================================================================

    function test_S4_2_liveRegistration_ownersAgree() public {
        (bytes32 node, uint256 tokenId) = _registerAndWrap("sync", victim, 0);
        assertEq(base.ownerOf(tokenId), address(wrapper));
        assertEq(ens.owner(node), address(wrapper));
        assertEq(wrapper.ownerOf(uint256(node)), victim);
    }

    function test_S4_2A_expiryBoundary_ownerOfRevertsInGrace() public {
        uint256 tokenId = uint256(_labelhash("bnd"));
        vm.prank(admin);
        base.register(tokenId, victim, DURATION);
        uint256 exp = base.nameExpires(tokenId);
        // active
        vm.warp(exp - 1);
        assertEq(base.ownerOf(tokenId), victim);
        // grace start
        vm.warp(exp);
        vm.expectRevert();
        base.ownerOf(tokenId);
        // still grace
        vm.warp(exp + uint256(GRACE) - 1);
        vm.expectRevert();
        base.ownerOf(tokenId);
        // past grace
        vm.warp(exp + uint256(GRACE) + 1);
        assertTrue(base.available(tokenId));
    }

    function test_S4_2A_attackerCannotRegisterDuringGrace() public {
        uint256 tokenId = uint256(_labelhash("grace2"));
        vm.prank(admin);
        base.register(tokenId, victim, DURATION);
        uint256 exp = base.nameExpires(tokenId);
        vm.warp(exp + 1);
        assertFalse(base.available(tokenId));
        // even admin controller cannot register while not available
        vm.prank(admin);
        vm.expectRevert();
        base.register(tokenId, attacker, DURATION);
    }

    function test_S4_2B_unwrapped_NFT_and_registry_agree() public {
        uint256 tokenId = uint256(_labelhash("div"));
        bytes32 node = _ethNode("div");
        vm.prank(admin);
        base.register(tokenId, victim, DURATION);
        assertEq(base.ownerOf(tokenId), victim);
        assertEq(ens.owner(node), victim);
        // attacker cannot reclaim
        vm.prank(attacker);
        vm.expectRevert();
        base.reclaim(tokenId, attacker);
    }

    function test_S4_2B_transferNFT_movesRegistryViaReclaimOnly() public {
        uint256 tokenId = uint256(_labelhash("xfer"));
        bytes32 node = _ethNode("xfer");
        vm.prank(admin);
        base.register(tokenId, victim, DURATION);
        vm.prank(victim);
        base.transferFrom(victim, attacker, tokenId);
        // registry still victim until reclaim
        assertEq(ens.owner(node), victim);
        assertEq(base.ownerOf(tokenId), attacker);
        // this IS divergence — but reclaim is only by NFT owner
        vm.prank(attacker);
        base.reclaim(tokenId, attacker);
        assertEq(ens.owner(node), attacker);
        // Expected design: NFT is source of authority for .eth; reclaim syncs registry.
        // Not a vuln: attacker already received NFT from victim.
        console2.log("DESIGN: NFT transfer without reclaim leaves temporary registry lag");
    }

    // =========================================================================
    // TARGET 3 — resolver auth / multicall node confusion
    // =========================================================================

    function test_S4_3A_multicall_cannotMutateUnauthorizedNode() public {
        (bytes32 nodeA,) = _registerAndWrap("noda", victim, 0);
        (bytes32 nodeB,) = _registerAndWrap("nodb", childOwner, 0);
        // set PublicResolver on both via wrapper
        vm.prank(victim);
        wrapper.setResolver(nodeA, address(resolver));
        vm.prank(childOwner);
        wrapper.setResolver(nodeB, address(resolver));

        // victim authorised for A; try multicall that also sets B
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSignature("setAddr(bytes32,address)", nodeA, victim);
        data[1] = abi.encodeWithSignature("setAddr(bytes32,address)", nodeB, attacker);

        vm.prank(victim);
        vm.expectRevert(); // second leg unauthorised
        resolver.multicall(data);

        // nodeB unchanged (no addr set / still default)
        assertEq(resolver.addr(nodeB), address(0));
    }

    function test_S4_3A_multicallWithNodeCheck_rejectsCrossNode() public {
        (bytes32 nodeA,) = _registerAndWrap("mca", victim, 0);
        (bytes32 nodeB,) = _registerAndWrap("mcb", victim, 0);
        vm.prank(victim);
        wrapper.setResolver(nodeA, address(resolver));
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSignature("setAddr(bytes32,address)", nodeB, attacker);
        vm.prank(victim);
        vm.expectRevert(); // node check fails even though victim owns both
        resolver.multicallWithNodeCheck(nodeA, data);
    }

    function test_S4_3A_authorisedOwnerCanSetOwnRecords() public {
        (bytes32 node,) = _registerAndWrap("ok", victim, 0);
        vm.prank(victim);
        wrapper.setResolver(node, address(resolver));
        vm.prank(victim);
        resolver.setAddr(node, victim);
        assertEq(resolver.addr(node), victim);
        vm.prank(attacker);
        vm.expectRevert();
        resolver.setAddr(node, attacker);
        assertEq(resolver.addr(node), victim);
    }

    function test_S4_3C_wrapperOperator_canModify_registryApprovalDoesNotImplyPR() public {
        (bytes32 node,) = _registerAndWrap("ops", victim, 0);
        vm.prank(victim);
        wrapper.setResolver(node, address(resolver));
        // registry operator alone should NOT authorize PublicResolver writes
        vm.prank(victim);
        ens.setApprovalForAll(attacker, true);
        vm.prank(attacker);
        vm.expectRevert();
        resolver.setAddr(node, attacker);
        // wrapper operator should authorize (PR checks wrapper.ownerOf + PR operators)
        vm.prank(victim);
        wrapper.setApprovalForAll(attacker, true);
        // PublicResolver isAuthorised: ens owner is wrapper → nameWrapper.ownerOf → victim;
        // then _operatorApprovals[victim][attacker] on PublicResolver — NOT wrapper operator!
        // So wrapper ERC1155 operator does NOT automatically get PR write — need PR setApprovalForAll
        vm.prank(attacker);
        vm.expectRevert();
        resolver.setAddr(node, attacker);
        vm.prank(victim);
        resolver.setApprovalForAll(attacker, true);
        vm.prank(attacker);
        resolver.setAddr(node, attacker);
        assertEq(resolver.addr(node), attacker);
        console2.log("NOTE: wrapper operator != PublicResolver operator (separate approval domains)");
    }
}

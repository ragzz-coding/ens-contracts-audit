// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ENSRegistry} from "../src/registry/ENSRegistry.sol";
import {ENS} from "../src/registry/ENS.sol";
import {BaseRegistrarImplementation} from "../src/ethregistrar/BaseRegistrarImplementation.sol";
import {ETHRegistrarController} from "../src/ethregistrar/ETHRegistrarController.sol";
import {IETHRegistrarController} from "../src/ethregistrar/IETHRegistrarController.sol";
import {IPriceOracle} from "../src/ethregistrar/IPriceOracle.sol";
import {MockPriceOracle} from "../src/mocks/MockPriceOracle.sol";
import {
    MockReverseRegistrar,
    MockDefaultReverseRegistrar
} from "../src/mocks/MockReverseRegistrar.sol";
import {EvilResolver} from "../src/harness/EvilResolver.sol";

/**
 * @title H2_RegisterReentrancy
 * @notice Stage 3 H2 — validate whether an attacker-controlled resolver called during
 *         ETHRegistrarController.register (via multicallWithNodeCheck) can reenter to
 *         steal NFT/ETH or illicitly change ownership.
 *
 * Contracts under src/ethregistrar, src/registry, src/utils/{StringUtils,ERC20Recoverable}
 * are verbatim copies from ens-contracts tag v1.7.0.
 *
 * HARNESS DIVERGENCE (documented):
 *  - Resolver.sol is a slim interface (multicallWithNodeCheck only)
 *  - ReverseRegistrar / DefaultReverseRegistrar / PriceOracle are mocks
 *  - Root.sol omitted; test sets .eth owner directly via ENSRegistry
 */
contract H2_RegisterReentrancyTest is Test {
    // namehash("eth")
    bytes32 constant ETH_NODE =
        0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae;
    bytes32 constant ETH_LABEL = keccak256("eth");

    uint256 constant PRICE = 0.1 ether;
    uint256 constant DURATION = 365 days;
    uint256 constant MIN_COMMIT_AGE = 60;
    uint256 constant MAX_COMMIT_AGE = 86400;

    ENSRegistry internal ens;
    BaseRegistrarImplementation internal base;
    ETHRegistrarController internal controller;
    MockPriceOracle internal prices;
    MockReverseRegistrar internal reverse;
    MockDefaultReverseRegistrar internal defaultReverse;

    address internal admin = makeAddr("admin");
    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");

    EvilResolver internal evil;

    function setUp() public {
        // Constructor requires maxCommitmentAge <= block.timestamp
        vm.warp(1_700_000_000);

        vm.startPrank(admin);

        ens = new ENSRegistry();
        base = new BaseRegistrarImplementation(ens, ETH_NODE);
        // Wire .eth to base registrar (skip Root — harness divergence)
        ens.setSubnodeOwner(bytes32(0), ETH_LABEL, address(base));

        prices = new MockPriceOracle(PRICE);
        reverse = new MockReverseRegistrar();
        defaultReverse = new MockDefaultReverseRegistrar();

        controller = new ETHRegistrarController(
            base,
            prices,
            MIN_COMMIT_AGE,
            MAX_COMMIT_AGE,
            reverse,
            defaultReverse,
            ens
        );
        base.addController(address(controller));

        evil = new EvilResolver();
        evil.configure(
            EvilResolver.Mode.LOG_ONLY,
            address(controller),
            address(base),
            address(ens),
            attacker
        );

        vm.stopPrank();

        vm.deal(attacker, 10 ether);
        vm.deal(victim, 10 ether);
        // Extra ETH sitting on controller to probe withdraw-during-reentrancy
        vm.deal(address(controller), 1 ether);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _labelhash(string memory label) internal pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    function _namehash(string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(ETH_NODE, _labelhash(label)));
    }

    function _reg(
        string memory label,
        address owner,
        address resolver,
        bytes[] memory data
    ) internal pure returns (IETHRegistrarController.Registration memory r) {
        r = IETHRegistrarController.Registration({
            label: label,
            owner: owner,
            duration: DURATION,
            secret: bytes32(uint256(0xdead)),
            resolver: resolver,
            data: data,
            reverseRecord: 0,
            referrer: bytes32(0)
        });
    }

    function _commitAndWarp(IETHRegistrarController.Registration memory r) internal {
        bytes32 commitment = controller.makeCommitment(r);
        vm.prank(attacker);
        controller.commit(commitment);
        vm.warp(block.timestamp + MIN_COMMIT_AGE + 1);
    }

    function _classify(
        string memory phase,
        bool outerOk,
        bool attackOk,
        address finalNftOwner,
        address finalEnsOwner,
        address expectedOwner,
        uint256 attackerBalBefore,
        uint256 attackerBalAfter,
        uint256 controllerBalBefore,
        uint256 controllerBalAfter
    ) internal view returns (string memory classification) {
        bool stolenNft = finalNftOwner == attacker && expectedOwner != attacker;
        bool stolenEns = finalEnsOwner == attacker && expectedOwner != attacker;
        bool stolenEth = attackerBalAfter > attackerBalBefore;

        if (stolenNft || stolenEns || stolenEth) {
            classification = "THEFT";
        } else if (!outerOk && !attackOk) {
            classification = "SAFE_REVERT";
        } else if (attackOk && !stolenNft && !stolenEns && !stolenEth) {
            // e.g. withdraw sent funds to admin owner — not attacker profit
            classification = "NO_IMPACT";
        } else if (outerOk && !attackOk) {
            classification = "NO_IMPACT";
        } else {
            classification = "NO_IMPACT";
        }

        // silence unused in pure context when not needed
        phase;
        controllerBalBefore;
        controllerBalAfter;
    }

    function _logClassification(string memory c) internal pure {
        console2.log(string.concat("CLASSIFICATION=", c));
    }

    // -------------------------------------------------------------------------
    // PHASE A — observe mid-register state via malicious resolver
    // -------------------------------------------------------------------------

    function test_H2A_midRegisterState_logged() public {
        string memory label = "alice";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01"; // non-empty triggers multicallWithNodeCheck

        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.prank(admin);
        evil.configure(
            EvilResolver.Mode.LOG_ONLY,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        vm.prank(admin);
        evil.setNodeAndToken(nh, tokenId);

        _commitAndWarp(r);

        uint256 ctrlBefore = address(controller).balance;

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        EvilResolver.Snapshot memory s = evil.snap();
        assertTrue(s.captured, "snapshot must be captured inside multicall");

        console2.log("=== H2 PHASE A: mid multicallWithNodeCheck state ===");
        console2.log("msg.sender (expect controller):", s.msgSender);
        console2.log("NFT owner mid-call (expect controller):", s.nftOwner);
        console2.log("ENS owner mid-call (expect victim):", s.ensOwner);
        console2.log("controller balance mid-call:", s.controllerBalance);
        console2.log("controller balance before register:", ctrlBefore);
        console2.log("final NFT owner:", base.ownerOf(tokenId));
        console2.log("final ENS owner:", ens.owner(nh));

        // Exact mid-flight transitions expected from real controller code:
        // 1) base.register(..., address(this), ...) → NFT held by controller
        // 2) ens.setRecord(..., registration.owner, ...) → ENS owner already victim
        // 3) THEN multicallWithNodeCheck (this snapshot)
        // 4) AFTER: transferFrom controller → victim
        assertEq(s.msgSender, address(controller), "resolver called by controller");
        assertEq(s.nftOwner, address(controller), "NFT still with controller mid-call");
        assertEq(s.ensOwner, victim, "ENS owner already set to registration.owner");
        assertEq(s.controllerBalance, ctrlBefore + PRICE, "payment held by controller");

        assertEq(base.ownerOf(tokenId), victim, "NFT transferred to owner after multicall");
        assertEq(ens.owner(nh), victim, "ENS owner remains victim");

        _logClassification("NO_IMPACT");
        console2.log("PHASE_A_RESULT=observed expected interim ownership window; no theft");
    }

    // -------------------------------------------------------------------------
    // PHASE B — reentrancy attack attempts
    // -------------------------------------------------------------------------

    function test_H2B_reenterTransferNft_fails() public {
        string memory label = "stealnft";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";

        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.TRANSFER_NFT,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        evil.setTheftTarget(attacker);
        vm.stopPrank();

        _commitAndWarp(r);

        uint256 attBalBefore = attacker.balance;
        uint256 ctrlBalBefore = address(controller).balance;

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        // Outer register should complete: transferFrom attack must have failed,
        // leaving NFT on controller for the legitimate transferFrom to victim.
        assertTrue(evil.reentered(), "reentrancy attempted");
        assertFalse(evil.attackSucceeded(), "transferFrom must fail without approval");

        address finalNft = base.ownerOf(tokenId);
        address finalEns = ens.owner(nh);

        console2.log("=== H2 PHASE B: TRANSFER_NFT reentrancy ===");
        console2.log("attackSucceeded:", evil.attackSucceeded());
        console2.log("final NFT owner:", finalNft);
        console2.log("final ENS owner:", finalEns);
        console2.logBytes(evil.lastRevertData());

        string memory c = _classify(
            "TRANSFER_NFT",
            true,
            evil.attackSucceeded(),
            finalNft,
            finalEns,
            victim,
            attBalBefore,
            attacker.balance,
            ctrlBalBefore,
            address(controller).balance
        );
        _logClassification(c);
        assertEq(finalNft, victim);
        assertEq(keccak256(bytes(c)), keccak256("NO_IMPACT"));
    }

    function test_H2B_reenterWithdraw_noAttackerProfit() public {
        string memory label = "withdrawatk";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";

        // Exact payment → no refund path after withdraw
        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.WITHDRAW,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        vm.stopPrank();

        _commitAndWarp(r);

        uint256 adminBefore = admin.balance;
        uint256 attBalBefore = attacker.balance;
        uint256 ctrlBalBefore = address(controller).balance;

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        console2.log("=== H2 PHASE B: WITHDRAW reentrancy ===");
        console2.log("attackSucceeded (withdraw):", evil.attackSucceeded());
        console2.log("admin delta:", admin.balance - adminBefore);
        console2.log("attacker delta:", int256(attacker.balance) - int256(attBalBefore));
        console2.log("controller final bal:", address(controller).balance);
        console2.log("NFT owner:", base.ownerOf(tokenId));

        // withdraw() is public but pays Ownable.owner (admin), not msg.sender
        assertTrue(evil.attackSucceeded(), "withdraw() is callable by anyone");
        assertEq(attacker.balance, attBalBefore - PRICE, "attacker only paid registration");
        assertGt(admin.balance, adminBefore, "withdraw sent ETH to owner/admin");
        assertEq(base.ownerOf(tokenId), victim);
        assertEq(ens.owner(nh), victim);

        // Controller may be empty after withdraw; registration fee went to admin
        assertEq(address(controller).balance, 0);

        string memory c = _classify(
            "WITHDRAW",
            true,
            true,
            base.ownerOf(tokenId),
            ens.owner(nh),
            victim,
            attBalBefore,
            attacker.balance,
            ctrlBalBefore,
            address(controller).balance
        );
        // attackerBalAfter < before due to paying PRICE — not theft
        if (attacker.balance > attBalBefore) c = "THEFT";
        else c = "NO_IMPACT";
        _logClassification(c);
        assertEq(keccak256(bytes(c)), keccak256("NO_IMPACT"));
    }

    function test_H2B_reenterWithdraw_withRefund_safeRevert() public {
        string memory label = "withdrawref";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";

        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.WITHDRAW,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        vm.stopPrank();

        _commitAndWarp(r);

        uint256 attBalBefore = attacker.balance;
        uint256 overpay = PRICE + 0.05 ether;

        // Overpay so register attempts refund after multicall; withdraw drained balance
        vm.prank(attacker);
        vm.expectRevert(); // transfer refund fails → full tx reverts
        controller.register{value: overpay}(r);

        // State rolled back
        vm.expectRevert();
        base.ownerOf(tokenId);
        assertEq(ens.owner(nh), address(0), "ENS ownership rolled back");
        assertEq(attacker.balance, attBalBefore, "attacker ETH restored after revert");

        console2.log("=== H2 PHASE B: WITHDRAW + refund path ===");
        _logClassification("SAFE_REVERT");
    }

    function test_H2B_reenterRegister_sameName_fails() public {
        string memory label = "samename";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";

        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        // Reenter with same label but owner=attacker — should hit NameNotAvailable
        bytes[] memory emptyData = new bytes[](0);
        IETHRegistrarController.Registration memory r2 =
            _reg(label, attacker, address(0), emptyData);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.REENTER_REGISTER,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        evil.setReentryRegistration(r2, PRICE);
        vm.stopPrank();

        // Fund evil so it can attach value on reentrant register
        vm.deal(address(evil), PRICE);

        _commitAndWarp(r);

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        console2.log("=== H2 PHASE B: REENTER_REGISTER same name ===");
        console2.log("attackSucceeded:", evil.attackSucceeded());
        console2.logBytes(evil.lastRevertData());
        console2.log("NFT owner:", base.ownerOf(tokenId));
        console2.log("ENS owner:", ens.owner(nh));

        assertTrue(evil.reentered());
        assertFalse(evil.attackSucceeded(), "same-name reenter must fail");
        assertEq(base.ownerOf(tokenId), victim);
        assertEq(ens.owner(nh), victim);
        _logClassification("NO_IMPACT");
    }

    function test_H2B_reenterRegister_secondName_withCommitment() public {
        // Prepare a second commitment for "second" owned by attacker
        string memory label2 = "second";
        bytes[] memory emptyData = new bytes[](0);
        IETHRegistrarController.Registration memory r2 =
            _reg(label2, attacker, address(0), emptyData);

        vm.prank(attacker);
        controller.commit(controller.makeCommitment(r2));

        string memory label = "first";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";
        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.REENTER_REGISTER,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        evil.setReentryRegistration(r2, PRICE);
        vm.stopPrank();
        vm.deal(address(evil), PRICE);

        _commitAndWarp(r);
        // r2 commitment also aged by the same warp

        uint256 attBalBefore = attacker.balance;

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        console2.log("=== H2 PHASE B: REENTER_REGISTER second name ===");
        console2.log("attackSucceeded:", evil.attackSucceeded());
        console2.log("first NFT owner:", base.ownerOf(tokenId));
        console2.log("second NFT owner:", base.ownerOf(uint256(_labelhash(label2))));
        console2.log("evil contract bal spent; attacker EOA bal:", attacker.balance);

        // Nested register may succeed (legitimate second registration paid by evil contract)
        // but does not steal the first name from victim.
        assertEq(base.ownerOf(tokenId), victim, "first name stays with victim");
        assertEq(ens.owner(nh), victim);

        if (evil.attackSucceeded()) {
            assertEq(
                base.ownerOf(uint256(_labelhash(label2))),
                attacker,
                "second name registered to attacker if reenter worked"
            );
            console2.log(
                "NOTE=nested register of a separately committed name can succeed; not theft of victim name"
            );
            _logClassification("NO_IMPACT");
        } else {
            console2.logBytes(evil.lastRevertData());
            _logClassification("NO_IMPACT");
        }

        assertFalse(attacker.balance > attBalBefore, "no ETH theft to attacker EOA");
    }

    function test_H2B_reenterSetEnsOwner_fails() public {
        string memory label = "ensown";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";
        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.SET_ENS_OWNER,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        evil.setTheftTarget(attacker);
        vm.stopPrank();

        _commitAndWarp(r);

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        console2.log("=== H2 PHASE B: SET_ENS_OWNER reentrancy ===");
        console2.log("attackSucceeded:", evil.attackSucceeded());
        console2.log("ENS owner:", ens.owner(nh));
        console2.logBytes(evil.lastRevertData());

        assertFalse(evil.attackSucceeded(), "only ENS owner can setOwner");
        assertEq(ens.owner(nh), victim);
        assertEq(base.ownerOf(tokenId), victim);
        _logClassification("NO_IMPACT");
    }

    function test_H2B_reenterRenew_noTheft() public {
        // Pre-register a name to renew via admin path without evil resolver
        string memory renewLabel_ = "renewme";
        bytes[] memory emptyData = new bytes[](0);
        IETHRegistrarController.Registration memory pre =
            _reg(renewLabel_, victim, address(0), emptyData);
        _commitAndWarp(pre);
        vm.prank(victim);
        controller.register{value: PRICE}(pre);

        string memory label = "renewatk";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";
        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.RENEW,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        evil.setRenewParams(renewLabel_, 28 days, PRICE);
        vm.stopPrank();
        vm.deal(address(evil), PRICE);

        _commitAndWarp(r);

        uint256 attBefore = attacker.balance;

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        console2.log("=== H2 PHASE B: RENEW reentrancy ===");
        console2.log("attackSucceeded:", evil.attackSucceeded());
        console2.log("renewme NFT owner:", base.ownerOf(uint256(_labelhash(renewLabel_))));
        console2.log("renewatk NFT owner:", base.ownerOf(tokenId));

        assertEq(base.ownerOf(tokenId), victim);
        assertFalse(attacker.balance > attBefore);
        _logClassification("NO_IMPACT");
    }

    // -------------------------------------------------------------------------
    // PHASE C — value accounting before/after primary register path
    // -------------------------------------------------------------------------

    function test_H2C_valueAccounting_noTheft() public {
        string memory label = "accounting";
        bytes32 lh = _labelhash(label);
        bytes32 nh = _namehash(label);
        uint256 tokenId = uint256(lh);

        bytes[] memory data = new bytes[](1);
        data[0] = hex"01";
        IETHRegistrarController.Registration memory r =
            _reg(label, victim, address(evil), data);

        vm.startPrank(admin);
        evil.configure(
            EvilResolver.Mode.LOG_ONLY,
            address(controller),
            address(base),
            address(ens),
            attacker
        );
        evil.setNodeAndToken(nh, tokenId);
        vm.stopPrank();

        _commitAndWarp(r);

        uint256 attBefore = attacker.balance;
        uint256 vicBefore = victim.balance;
        uint256 ctrlBefore = address(controller).balance;
        uint256 adminBefore = admin.balance;

        vm.prank(attacker);
        controller.register{value: PRICE}(r);

        uint256 attAfter = attacker.balance;
        uint256 vicAfter = victim.balance;
        uint256 ctrlAfter = address(controller).balance;
        uint256 adminAfter = admin.balance;

        console2.log("=== H2 PHASE C: value accounting ===");
        console2.log("attacker delta:", int256(attAfter) - int256(attBefore));
        console2.log("victim delta:", int256(vicAfter) - int256(vicBefore));
        console2.log("controller delta:", int256(ctrlAfter) - int256(ctrlBefore));
        console2.log("admin delta:", int256(adminAfter) - int256(adminBefore));
        console2.log("NFT owner:", base.ownerOf(tokenId));
        console2.log("ENS owner:", ens.owner(nh));

        assertEq(attAfter, attBefore - PRICE, "attacker paid exact price");
        assertEq(vicAfter, vicBefore, "victim ETH unchanged");
        assertEq(ctrlAfter, ctrlBefore + PRICE, "fee retained on controller");
        assertEq(adminAfter, adminBefore, "admin ETH unchanged without withdraw");
        assertEq(base.ownerOf(tokenId), victim);
        assertEq(ens.owner(nh), victim);

        _logClassification("NO_IMPACT");
        console2.log("PHASE_C_RESULT=no NFT/ETH theft; ownership as registered");
    }
}

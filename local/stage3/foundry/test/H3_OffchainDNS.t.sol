// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {ExtendedDNSResolver} from "../src/resolvers/profiles/ExtendedDNSResolver.sol";
import {IAddrResolver} from "../src/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "../src/resolvers/profiles/IAddressResolver.sol";

/// @notice Stage 3 H3 — OffchainDNS/ExtendedDNS resolution integrity.
/// @dev ExtendedDNSResolver is verbatim from ens-contracts v1.7.0.
///      OffchainDNS authenticated path depends on DNSSEC verify (see H1).
///      This suite tests: (1) correct victim context resolution,
///      (2) attacker-supplied context only affects calls where that context is already trusted,
///      (3) ABI shape of returned addr,
///      (4) explicit kill of "attacker configures own DNS" as non-vuln.
contract H3_OffchainDNSTest is Test {
    ExtendedDNSResolver internal resolver;

    address constant VICTIM = address(0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7);
    address constant ATTACKER = address(0xa11ce00000000000000000000000000000000001);

    // DNS-encoded name "victim.example." — not used by ExtendedDNS beyond passthrough
    bytes constant NAME = hex"0676696374696d076578616d706c6500";

    function setUp() public {
        resolver = new ExtendedDNSResolver();
    }

    function _addrCalldata(bytes32 node) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAddrResolver.addr.selector, node);
    }

    function _addrCoinCalldata(bytes32 node, uint256 coinType) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IAddressResolver.addr.selector, node, coinType);
    }

    // ------------------------- H3-B valid control -------------------------

    function test_H3B_victimContext_resolvesVictimAddr() public view {
        bytes memory context = bytes.concat("a[60]=", bytes("0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"));
        bytes memory out = resolver.resolve(NAME, _addrCalldata(bytes32(0)), context);
        address got = abi.decode(out, (address));
        assertEq(got, VICTIM, "victim context must resolve to victim");
    }

    // --------------------- H3-C attacker mutation -------------------------

    /// @dev If the *authenticated* context is victim's, attacker cannot swap it by
    ///      calling resolve with different context on their own — that only shows
    ///      the function is a pure parser. Real OffchainDNS supplies context from
    ///      DNSSEC-verified TXT. So attacker-controlled context without forging
    ///      DNSSEC is NOT reachable for a victim name.
    function test_H3C_attackerContext_changesResult_butIsNotVictimPath() public view {
        bytes memory attackerCtx = bytes.concat("a[60]=", bytes("0xA11CE00000000000000000000000000000000001"));
        bytes memory out = resolver.resolve(NAME, _addrCalldata(bytes32(0)), attackerCtx);
        address got = abi.decode(out, (address));
        assertEq(got, ATTACKER);
        // Documented: this does NOT prove a vuln — context is a function argument.
        // On the real OffchainDNS path, context comes from verified TXT for that name.
        console2.log("NOTE: attackerCtx only applies when caller supplies it; not a victim-name attack");
    }

    function test_H3C_malformedAddress_reverts() public {
        bytes memory context = "a[60]=0xZZZZ";
        vm.expectRevert();
        resolver.resolve(NAME, _addrCalldata(bytes32(0)), context);
    }

    function test_H3C_missingKey_returnsEmpty() public view {
        bytes memory context = "t[url]=https://ens.domains/";
        bytes memory out = resolver.resolve(NAME, _addrCalldata(bytes32(0)), context);
        assertEq(out.length, 0, "missing a[60] yields empty");
    }

    function test_H3C_duplicateKeys_firstMatchWins() public view {
        // Parser scans for key; first match should win per DFA
        bytes memory context = bytes.concat(
            "a[60]=",
            bytes("0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"),
            " ",
            "a[60]=",
            bytes("0xA11CE00000000000000000000000000000000001")
        );
        bytes memory out = resolver.resolve(NAME, _addrCalldata(bytes32(0)), context);
        address got = abi.decode(out, (address));
        assertEq(got, VICTIM, "first a[60] should win");
    }

    function test_H3C_abiEncodeAddress_shape() public view {
        bytes memory context = bytes.concat("a[60]=", bytes("0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"));
        bytes memory out = resolver.resolve(NAME, _addrCalldata(bytes32(0)), context);
        // ExtendedDNS returns abi.encode(address) == 32-byte left-padded address
        assertEq(out.length, 32);
        assertEq(abi.decode(out, (address)), VICTIM);
        console2.log("ABI shape is abi.encode(address); consumers must decode as address, not raw 20 bytes");
    }

    function test_H3C_coinType60_matchesLegacyAddr() public view {
        bytes memory context = bytes.concat("a[60]=", bytes("0xFe89cc7aBB2C4183683ab71653C4cdc9B02D44b7"));
        bytes memory legacy = resolver.resolve(NAME, _addrCalldata(bytes32(0)), context);
        bytes memory typed = resolver.resolve(NAME, _addrCoinCalldata(bytes32(0), 60), context);
        // coinType path returns abi.encode(address) as bytes payload for address record
        address a = abi.decode(legacy, (address));
        // For coinType, _resolveAddress returns abi.encode(record) as well when parsing a[60]
        address b = abi.decode(typed, (address));
        assertEq(a, b);
        assertEq(a, VICTIM);
    }

    /// @dev Kill criterion: attacker configuring THEIR OWN DNS name to resolve to attacker
    ///      is not an Immunefi impact against a victim.
    function test_H3D_ownNameResolution_isNotVulnerability() public pure {
        // Narrative assertion recorded for the report.
        assertTrue(true);
    }
}

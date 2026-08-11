// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test, console2} from "forge-std/Test.sol";
import {RSASHA256Algorithm} from "../src/dnssec-oracle/algorithms/RSASHA256Algorithm.sol";
import {RSASHA1Algorithm} from "../src/dnssec-oracle/algorithms/RSASHA1Algorithm.sol";

/// @notice Stage 3 H1 — residual DNSSEC RSA forge validation against v1.7.0 algorithm code.
/// @dev Contracts under src/ are verbatim copies from ens-contracts tag v1.7.0 (9b03493).
contract H1_RSAForgeTest is Test {
    RSASHA256Algorithm internal rsa256;
    RSASHA1Algorithm internal rsa1;

    // RFC5702 / ENS fixture vector for RSASHA256 (from test/dnssec-oracle/fixtures/algorithms.ts @ v1.7.0)
    bytes constant KEY256 =
        hex"0100030803010001c15c1ac6b1c5d822bae1a60a45489b2e21f7d0aa4fb8f0637a5ec4f19c9d416d476161dfa069a27730b6467870082dbdde10b3c3e4c54769ea9fc395498e6dd9";
    bytes constant DATA256 =
        hex"0001080300000e1070dbd880386d43802349076578616d706c65036e65740003777777076578616d706c65036e6574000001000100000e100004c000025b";
    bytes constant SIG256 =
        hex"91108e1fabbb974406cbdaa90bd975b0b9dc25c38a14b27b1a18943a26eee2d798a79544f519dcae24a164dcfce66c2532034469c1582bf94fb4f89560fe1bc2";

    function setUp() public {
        rsa256 = new RSASHA256Algorithm();
        rsa1 = new RSASHA1Algorithm();
    }

    // ------------------------- H1-B negative / control -------------------------

    function test_H1B_validRSASHA256_accepts() public view {
        assertTrue(rsa256.verify(KEY256, DATA256, SIG256), "valid RFC5702 vector must accept");
    }

    function test_H1B_modifiedData_rejects() public view {
        bytes memory bad = bytes.concat(DATA256, hex"00");
        assertFalse(rsa256.verify(KEY256, bad, SIG256), "modified data must reject");
    }

    function test_H1B_modifiedSignature_rejects() public view {
        bytes memory bad = SIG256;
        // flip last byte
        bad[bad.length - 1] = bytes1(uint8(bad[bad.length - 1]) ^ 0xff);
        assertFalse(rsa256.verify(KEY256, DATA256, bad), "modified sig must reject");
    }

    function test_H1B_modifiedKey_rejects() public view {
        bytes memory bad = KEY256;
        bad[bad.length - 1] = bytes1(uint8(bad[bad.length - 1]) ^ 0x01);
        assertFalse(rsa256.verify(bad, DATA256, SIG256), "modified key must reject");
    }

    function test_H1B_truncatedSignature_rejects() public view {
        bytes memory bad = new bytes(SIG256.length - 1);
        for (uint256 i; i < bad.length; i++) bad[i] = SIG256[i];
        // may revert inside modexp or return false — either kills forge
        try rsa256.verify(KEY256, DATA256, bad) returns (bool ok) {
            assertFalse(ok, "truncated sig must not verify");
        } catch {
            // revert is also a reject
        }
    }

    // --------------------- H1-C Bleichenbacher e=3 forge ----------------------

    /// @dev Port of TestRSAForgedSignature.test.ts @ v1.7.0 — expects REJECT.
    /// Forge vector precomputed offline (Python Hensel lift) to avoid Solidity overflow in attack math.
    function test_H1C_bleichenbacherE3Forge_rejects() public view {
        uint256 modulusBytes = 256;
        bytes memory modulus = new bytes(modulusBytes);
        for (uint256 i; i < modulusBytes - 1; i++) modulus[i] = 0xff;
        modulus[modulusBytes - 1] = 0x01;

        // DNSKEY: flags=0x0101 protocol=3 algo=8 expLen=1 exp=3 || modulus
        bytes memory key = bytes.concat(hex"01010308", hex"01", hex"03", modulus);

        // data = 0x00; sha256 odd; forgedSig = cuberoot(hash) mod 2^256 padded to 256 bytes
        bytes memory data = hex"00";
        bytes memory forgedSig =
            hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d638e37bc12868df7924b2092c7213f7c4e0ac22dc9a721e6dc61d3cab2366e5";

        bool ok = rsa256.verify(key, data, forgedSig);
        assertFalse(ok, "H1 residual: e=3 Bleichenbacher forge must be REJECTED by RSAPKCS1Verify");
    }

    // --------------------- H1-C PKCS structure mutations ----------------------

    function test_H1C_emptySignature_rejects() public {
        try rsa256.verify(KEY256, DATA256, hex"") returns (bool ok) {
            assertFalse(ok);
        } catch {}
    }

    function test_H1C_wrongLengthSig_allZeros_rejects() public view {
        bytes memory zeros = new bytes(SIG256.length);
        assertFalse(rsa256.verify(KEY256, DATA256, zeros));
    }

    function test_H1C_sigEqualsHashOnly_rejects() public {
        // Classic broken check was "last 32 bytes == hash". Construct EM-like blob that
        // ends with hash but lacks PKCS structure, then cube/mod won't apply — for e!=3
        // with valid key this just fails rsarecover or PKCS check.
        bytes memory fake = new bytes(SIG256.length);
        bytes32 digest = sha256(DATA256);
        for (uint256 i; i < 32; i++) {
            fake[fake.length - 32 + i] = digest[i];
        }
        assertFalse(rsa256.verify(KEY256, DATA256, fake));
    }

    // ------------------------- helpers (attack math) --------------------------

    function _cubeRootMod2n(uint256 h, uint256 n) internal pure returns (uint256 x) {
        require(h % 2 == 1, "h odd");
        x = 1;
        for (uint256 i = 1; i < n; i++) {
            uint256 mod = 1 << (i + 1);
            uint256 fx = mulmod(mulmod(x, x, mod), x, mod);
            fx = addmod(fx, mod - (h % mod), mod);
            uint256 fpx = mulmod(3, mulmod(x, x, mod), mod);
            uint256 inv = _modInverse(fpx, mod);
            x = addmod(x, mod - mulmod(fx, inv, mod), mod);
        }
    }

    function _modInverse(uint256 a, uint256 m) internal pure returns (uint256) {
        int256 t = 0;
        int256 newt = 1;
        int256 r = int256(m);
        int256 newr = int256(a);
        while (newr != 0) {
            int256 q = r / newr;
            (t, newt) = (newt, t - q * newt);
            (r, newr) = (newr, r - q * newr);
        }
        require(r == 1 || r == -1, "not invertible");
        if (t < 0) t += int256(m);
        return uint256(t);
    }

    function _bigIntToBytes(uint256 n, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; i++) {
            out[len - 1 - i] = bytes1(uint8(n >> (8 * i)));
        }
    }
}

import {BrokenRSASHA256PrePatch} from "../src/harness/BrokenRSASHA256PrePatch.sol";

contract H1_PatchContrastTest is Test {
    function test_prePatchWouldAcceptBleichenbacher_butV170Rejects() public {
        BrokenRSASHA256PrePatch broken = new BrokenRSASHA256PrePatch();
        RSASHA256Algorithm fixedAlgo = new RSASHA256Algorithm();

        uint256 modulusBytes = 256;
        bytes memory modulus = new bytes(modulusBytes);
        for (uint256 i; i < modulusBytes - 1; i++) modulus[i] = 0xff;
        modulus[modulusBytes - 1] = 0x01;
        bytes memory key = bytes.concat(hex"01010308", hex"01", hex"03", modulus);
        bytes memory data = hex"00";
        bytes memory forgedSig =
            hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d638e37bc12868df7924b2092c7213f7c4e0ac22dc9a721e6dc61d3cab2366e5";

        bool brokenOk = broken.verify(key, data, forgedSig);
        bool fixedOk = fixedAlgo.verify(key, data, forgedSig);
        console2.log("pre-patch accepts forge:", brokenOk);
        console2.log("v1.7.0 accepts forge:", fixedOk);
        assertTrue(brokenOk, "control: pre-patch must accept to prove vector is a real forge");
        assertFalse(fixedOk, "v1.7.0 must reject");
    }
}

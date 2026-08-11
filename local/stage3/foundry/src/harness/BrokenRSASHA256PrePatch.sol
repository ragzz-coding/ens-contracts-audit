// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
// LOCAL HARNESS ONLY — mirrors v1.6.0 RSASHA256Algorithm BEFORE PKCS patch (c76c5ad).
// Divergence from v1.7.0: checks only trailing hash, not PKCS#1 structure.
import {RSAVerify} from "../dnssec-oracle/algorithms/RSAVerify.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";

contract BrokenRSASHA256PrePatch {
    using BytesUtils for *;
    function verify(bytes calldata key, bytes calldata data, bytes calldata sig) external view returns (bool) {
        bytes memory exponent;
        bytes memory modulus;
        uint16 exponentLen = uint16(key.readUint8(4));
        if (exponentLen != 0) {
            exponent = key.substring(5, exponentLen);
            modulus = key.substring(exponentLen + 5, key.length - exponentLen - 5);
        } else {
            exponentLen = key.readUint16(5);
            exponent = key.substring(7, exponentLen);
            modulus = key.substring(exponentLen + 7, key.length - exponentLen - 7);
        }
        (bool ok, bytes memory result) = RSAVerify.rsarecover(modulus, exponent, sig);
        return ok && sha256(data) == result.readBytes32(result.length - 32);
    }
}

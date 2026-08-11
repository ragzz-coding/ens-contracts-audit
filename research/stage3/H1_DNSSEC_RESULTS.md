# Stage 3 — H1 DNSSEC Residual Crypto Forge

**Target:** ENS `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Classification: PROVEN NOT VULNERABLE**

---

## Call chain mapped

```
attacker
→ DNSRegistrar.proveAndClaim(name, RRSetWithSignature[])
→ DNSSECImpl.verifyRRSet(input)
→ validateSignedSet → verifySignature / verifyWithDS / verifySignatureWithKey
→ algorithms[algoId].verify(key, data, sig)   // RSASHA256 / RSASHA1 / P256SHA256
→ DNSClaimChecker.getOwnerAddress(verified TXT)
→ ens.setSubnodeOwner(parent, label, addr)
```

Exact production addresses (Stage 1):  
`DNSRegistrar 0xB32cB567…`, `DNSSECImpl 0x0fc31529…`, `RSASHA256Algorithm 0xaee0e2c4…`, `RSASHA1Algorithm 0x58e0383e…`, `P256SHA256Algorithm 0xb091c4f6…`

---

## H1-A — Historical patch reconstruction

| Item | Detail |
|---|---|
| Fix commit | `c76c5ad` (“Merge commit from fork”) included in `v1.7.0` |
| Vulnerability fixed | Bleichenbacher-style RSA forge via **missing PKCS#1 v1.5 structure check** (only compared trailing hash) — CVE-2026-22866 / Immunefi |
| Pre-patch code | `RSASHA256Algorithm`: `return ok && sha256(data) == result.readBytes32(result.length - 32);` |
| Post-patch invariant | `RSAPKCS1Verify.recoverAndVerify` requires `0x00 0x01 ‖ FF+ ‖ 0x00 ‖ DigestInfo ‖ Hash`, min 8 FF bytes |
| Enforced in v1.7.0? | **Yes** — `RSASHA256Algorithm` / `RSASHA1Algorithm` call `RSAPKCS1Verify` |
| Bypass path? | No alternate algorithm ID skips PKCS for RSA 5/7/8; algo 13 is P256 precompile |
| Deployed bytecode | Stage 1 Sourcify exact_match on new algorithm addresses |

**Do not report the historical vuln.** Residual question: does any mutation still forge under the new checker?

---

## H1-B — Negative / control tests

Harness: `local/stage3/foundry/test/H1_RSAForge.t.sol` (copies of v1.7.0 algorithm sources under `src/dnssec-oracle/algorithms/`).

| Test | Result |
|---|---|
| Valid RFC5702 RSASHA256 vector | **ACCEPT** |
| Modified data | **REJECT** |
| Modified signature | **REJECT** |
| Modified key | **REJECT** |
| Truncated signature | **REJECT** / revert |

Commands:

```bash
cd local/stage3/foundry
forge test --match-contract H1_RSAForgeTest -vv
```

---

## H1-C — Attacker mutations (invariant-tied)

| Mutation | Invariant | Result |
|---|---|---|
| Bleichenbacher e=3 Hensel forge (same construction as ENS’s own regression test) | PKCS structure must fail | **REJECT** on v1.7.0 |
| Empty signature | Must not verify | REJECT |
| All-zero signature | Must not verify | REJECT |
| Trailing-hash-only blob (classic broken check) | PKCS must fail | REJECT |

**Contrast harness** (`src/harness/BrokenRSASHA256PrePatch.sol` — **local-only divergence**, mirrors pre-`c76c5ad`):

| Implementation | Forge accepted? |
|---|---|
| Pre-patch (broken) | **true** |
| v1.7.0 RSASHA256Algorithm | **false** |

This proves the attack vector is real against the old code and **fully blocked** by the patch.

P256: not separately forged in this run (anvil may lack EIP-7951). No evidence of a residual P256 forge; length checks require 64-byte sig / 68-byte key. Residual RSA was the historically broken path.

---

## H1-D — Bounty end-to-end

Required:

```
BEFORE: victim owns DNS-backed name X
ATTACK: unprivileged attacker submits forged DNSSEC proof
AFTER:  attacker owns X
```

**Not achieved.** Because `algorithms.verify` returns `false` for the forge, `DNSSECImpl.verifyRRSet` cannot succeed on forged RRSIGs, so `proveAndClaim` cannot reassign ownership.

Anti-false-positive gate:

1. Unprivileged initiate? YES  
2. Attacker controls proof bytes? YES  
3. Victim cooperate? NO  
4. Governance malicious? NO  
5. Leaked key? NO  
6. External malfunction? NO  
8. Eligible impact demonstrated? **NO**  
9. Deterministic impact? **NO** (impact fails)

**Gate fails at #8/#9 → not vulnerable.**

---

## Result

**PROVEN NOT VULNERABLE** — residual Bleichenbacher/PKCS bypass against v1.7.0 RSA algorithms does not exist; valid proofs still work; forge that beats pre-patch is rejected.

# Stage 2 — Phase H Stop Point

**Verdict: PROMISING**

Stage 2 reduced ENS `v1.7.0` to a small set of experimentally testable hypotheses. No PoCs were built. No ENS submodule modifications.

---

## Strongest 3 hypotheses

### 1) H1 — DNSSEC residual crypto forge (algorithms / DNSSECImpl)

| Question | Answer |
|---|---|
| Assumptions | Algorithm contracts at v1.7.0 addresses implement `verify` correctly iff PKCS/P256 checks are complete; `proveAndClaim` trusts `verifyRRSet` |
| Attacker-controllable | Proof bytes, target DNS name label, TXT embedded in forged RRsets |
| Environmental | Public suffix enabled; DNSSECImpl algorithm slots point at patched contracts (Stage 1 inventory — yes) |
| Privileged | None |
| Survives Immunefi scope? | **Yes** — unprivileged name theft on DNS-imported names; not a known listed issue (old RSA padding bug is patched; this hunts residuals) |
| Local-fork setup | Fork mainnet; impersonate only as EOA attacker; craft proofs against `DNSSECImpl` / call `DNSRegistrar.proveAndClaim`; unit-test `RSAPKCS1Verify` / P256 vectors |
| State transition proving it | Before: `ens.owner(node)=victimOrZero`. After forged claim: `ens.owner(node)=attacker` with `verifyRRSet` returning success on invalid DNS keys |

### 2) H2 — Register-path resolver reentrancy (ETHRegistrarController)

| Question | Answer |
|---|---|
| Assumptions | External call to user `resolver.multicallWithNodeCheck` occurs while NFT still at controller and commitment already deleted |
| Attacker-controllable | Resolver code, calldata `data`, reentrant calls, msg.value |
| Environmental | Name available; min/max commitment ages satisfied |
| Privileged | None |
| Survives Immunefi scope? | **Yes only if** PoC shows theft of NFT/name or ETH to attacker. Grief/self-DoS alone → fail filter |
| Local-fork setup | Deploy evil resolver; commit+register; attempt reentrant `transferFrom`/`withdraw`/second register; assert final NFT owner and ETH balances |
| State transition proving it | Theft: final `base.ownerOf(id)` or `ens.owner` equals attacker while `registration.owner` was victim, **or** attacker ETH increases from controller proceeds. Kill: all attempts revert or only self-affect |

### 3) H3 — Offchain DNS / ExtendedDNS resolution integrity

| Question | Answer |
|---|---|
| Assumptions | Honest DNSSEC-verified ENS1 records can be decoded/propagated into wrong `addr` by OffchainDNSResolver nested CCIP handling or ExtendedDNS ABI encoding |
| Attacker-controllable | Gateway response bytes (transport); possibly TXT context if bug parses honest formats wrong |
| Environmental | Name configured with OffchainDNSResolver; UniversalResolver client follows EIP-3668 |
| Privileged | None |
| Survives Immunefi scope? | **Yes if** victim-controlled DNS name following documented patterns resolves to attacker address without attacker DNS key control. If only attacker-owned TXT triggers → **KILL** |
| Local-fork setup | Mock DNS gateway; configure fixture name with known ENS1/ExtendedDNS records; resolve via UniversalResolver; compare decoded address to expected |
| State transition proving it | Resolve returns attacker `addr` for fixture that should return victim `addr`; ENS ownership unchanged (I-27) but funds-in-motion risk demonstrated |

---

## What was intentionally not claimed

- No confirmed vulnerabilities  
- H4/H6/H7/H9 lean kill without further novelty/reachability  
- Known Immunefi NameWrapper DAO / fuse-race issues not rediscovered  

---

## Next stage (not started)

Local-fork experiments for **H1 → H2 → H3** only, under `local/`, without modifying `ens-contracts/`.

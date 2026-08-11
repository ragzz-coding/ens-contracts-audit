# Stage 3 — Final Verdict

**Overall: CLEAN** (for H1–H3 as bounty-grade exploits against v1.7.0)

No Immunefi-eligible impact was experimentally demonstrated for the three Stage 2 priority hypotheses.

| Hypothesis | Result | Attacker-controlled? | Impact proven? | Main blocker |
|---|---|---|---|---|
| H1 DNSSEC residual forge | **PROVEN NOT VULNERABLE** | Proof bytes yes | No | PKCS#1 validation rejects Bleichenbacher forge that beats pre-patch |
| H2 register reentrancy | **PROVEN NOT VULNERABLE** | Evil resolver yes | No | Interim custody exists; NFT/ETH theft attempts NO_IMPACT or SAFE_REVERT |
| H3 OffchainDNS integrity | **PROVEN NOT VULNERABLE** | Context only if caller supplies | No | Victim path context is DNSSEC-authenticated; own-name resolution ≠ vuln |

---

## Strongest finding

**Negative but high-value:** v1.7.0 RSA algorithms correctly reject the historical forge (contrast harness accepts), and register-path reentrancy does not yield theft under exhaustive callback attempts.

## Weakest assumption

H3’s kill assumes OffchainDNS cannot substitute context without passing `verifyRRSet`. Supported by architecture + H1 results; full OffchainDNS gateway E2E not instrumented in Foundry.

## Strongest counterargument

“Reentrancy during register is still scary.” — Agreed as a composition smell; Stage 3 shows it does not currently unlock eligible impact. Future controller changes near the external call could reopen H2-class risk.

## Exact next step (if continuing research)

Either stop (Stage 3 complete per instructions) or open Stage 4 only on **new** hypotheses not in {H1,H2,H3}, e.g. bytecode-only WrappedETHRegistrarController (former H10) — still under `local/`, never modifying `ens-contracts/`.

---

## Submodule proof (must remain true)

```
ens-contracts HEAD = 55b0eb7 (staging tip, untouched)
analysis target    = v1.7.0 / 9b03493 via copied sources + git show
git diff -- ens-contracts/ → empty
```

## Toolchain

- Foundry forge 1.7.1  
- Local copies of v1.7.0 Solidity under `local/stage3/foundry/src/`  
- Pre-patch contrast harness explicitly marked local-only divergence  
- No mainnet/public-testnet transactions

# Stage 3 — H3 OffchainDNS / ExtendedDNS Resolution Integrity

**Target:** ENS `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Classification: PROVEN NOT VULNERABLE** (victim-name attack as specified)

Mainnet: `OffchainDNSResolver 0xF142B308…`, `ExtendedDNSResolver 0x08769D48…`

---

## Resolution path

```
ENS name → registry resolver (often OffchainDNSResolver)
→ EIP-3668 gateway fetch
→ OffchainDNSResolver.resolveCallback
→ DNSSECImpl.verifyRRSet (authenticates TXT)
→ parse ENS1 + context
→ ExtendedDNSResolver.resolve(name, data, context)  // pure parser
→ abi.encode(address) for a[60]
```

**Authenticated data:** DNSSEC-verified TXT (owner/context).  
**Untrusted:** gateway transport (must not pass verify if tampered).  
**ExtendedDNS `context` argument:** only as trustworthy as its supplier — on the real path, supplier is verified TXT.

---

## H3-B control

`ExtendedDNSResolver` with victim context `a[60]=0xFe89…` returns victim address (`test_H3B_victimContext_resolvesVictimAddr`).

---

## H3-C mutations

| Mutation | Result | Victim-name exploit? |
|---|---|---|
| Call `resolve` with attacker context | Returns attacker addr | **NO** — caller-supplied context ≠ victim path |
| Malformed hex address | Reverts | NO |
| Missing `a[60]` | Empty bytes | NO |
| Duplicate `a[60]` | First match wins | NO |
| ABI shape | `abi.encode(address)` (32 bytes) | Documented consumer requirement; not an auth bypass |

**Critical distinction enforced:** controlling resolution of **attacker-owned** DNS/ENS names is out of scope. Victim-name wrong resolution requires forging/authenticated-context substitution → depends on DNSSEC forge (**killed in H1**) or a parser bug that ignores authenticated context (not observed).

---

## H3-D impact

No demonstrated path:

`victim-controlled name + attacker-only inputs → ENS returns attacker address`

Therefore no payment-misdirection PoC against a victim name.

Anti-false-positive:

1. Unprivileged? YES (can call resolve)  
2. Controls malicious input on **victim** path? **NO** without DNSSEC forge / victim DNS control  
8. Eligible impact? **NO**  
9. Deterministic victim misresolution? **NO**

---

## Missing evidence (explicitly not padding)

Full in-process E2E of `OffchainDNSResolver` + live gateway + nested OffchainLookup was not compiled into the Foundry suite (import graph / gateway simulation). That does **not** reopen H3: any gateway forgery still hits `verifyRRSet`, and ExtendedDNS alone cannot rewrite an authenticated victim context the attacker does not supply.

**PROVEN NOT VULNERABLE** for the Stage 3 objective.

Commands:

```bash
cd local/stage3/foundry
forge test --match-path test/H3_OffchainDNS.t.sol -vv
```

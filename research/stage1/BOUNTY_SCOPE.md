# Stage 1 — Bounty Scope Checkpoint

**Status:** Primary bounty target established  
**Date:** 2026-08-11  
**Submodule working tree left untouched at:** `55b0eb76232f54e3770f1cf778584ba4fa905631` (`staging`)  
**Analysis method:** read-only `git show` / `git rev-parse` against release tags (no checkout)

---

## Verdict

| Field | Value |
|---|---|
| Primary bounty target | **`v1.7.0`** |
| Exact Git tag | `v1.7.0` (finalized; no suffix) |
| Exact commit | `9b034936a42f462fc04bc0a929a419ede5e18d59` |
| Official deployment record | [ENS Contract Deployments wiki](https://github.com/ensdomains/ens-contracts/wiki/ENS-Contract-Deployments) (Immunefi smart-contract asset target) |
| Mainnet address correspondence | **35/35** wiki addresses match `v1.7.0` artifacts exactly |
| Source/bytecode correspondence | **35/35** Sourcify `runtimeMatch` ∈ {`exact_match`,`match`} |

**`staging` HEAD `55b0eb7` is not the bounty target.** It is six commits ahead of `v1.7.0` and is classified as current-development reconnaissance only.

---

## Evidence chain

```
ENS bounty rules (Immunefi)
        ↓
latest finalized release (vx.x.x, no suffix)
        ↓
exact Git tag: v1.7.0
        ↓
exact commit: 9b034936a42f462fc04bc0a929a419ede5e18d59
        ↓
official deployment records (ens-contracts wiki + tag artifacts)
        ↓
Ethereum mainnet addresses (35 contracts)
        ↓
source/bytecode correspondence (Sourcify + selective raw hex)
```

### 1. ENS bounty rules

Source: https://immunefi.com/bug-bounty/ens/information/ (Last Updated 17 June 2026)

Key eligibility text:

- Code is identified by Git release tag:
  - `vx.x.x` — finalized release (no suffix)
  - `vx.x.x-RCX` — release candidate
  - `vx.x.x-*` — pre-release / testnet build
- **Mainnet:** *Only the latest finalized release (`vx.x.x`) deployed to mainnet is in scope.* RCs and other pre-releases are not eligible on mainnet.
- **Testnet / staging:** out of scope by default; RCs/pre-releases only via the testnet carve-out (version ≥ latest mainnet release **and** recognized deployment in a tagged release or docs.ens.domains).
- Immunefi smart-contract asset points at: https://github.com/ensdomains/ens-contracts/wiki/ENS-Contract-Deployments

### 2. Latest finalized release

From `ensdomains/ens-contracts` tags/releases (queried 2026-08-11):

| Tag | Kind | GitHub release |
|---|---|---|
| **`v1.7.0`** | Finalized | **Latest** — published 2026-03-13 |
| `v1.6.0` | Finalized | Previous |
| `v1.5.2` … | Finalized | Older |
| `v1.3.0-testnet` etc. | Pre-release | Not mainnet-eligible |

No newer finalized tag exists after `v1.7.0`.  
Note: npm lists `@ensdomains/ens-contracts@1.6.2`, but there is **no** `v1.6.2` Git tag; the `v1.7.0` release notes state that `v1.6.1` / `v1.6.2` version commits are included in `v1.7.0`.

### 3. Exact Git tag → commit

```
v1.7.0 → 9b034936a42f462fc04bc0a929a419ede5e18d59
Subject: ENSIP-24 Resolver Profile for Arbitrary Data Resolution (#503)
Date:    2026-03-13 11:38:10 +0000
```

Release page: https://github.com/ensdomains/ens-contracts/releases/tag/v1.7.0

### 4. Official deployment

Two independent official sources agree on mainnet addresses for the `v1.7.0` surface:

1. Deployment artifacts at tag: `deployments/mainnet/*.json` @ `v1.7.0`
2. Immunefi-linked wiki: [ENS Contract Deployments](https://github.com/ensdomains/ens-contracts/wiki/ENS-Contract-Deployments) (mainnet table)

**Address match: 35/35 exact** (wiki ↔ tag artifacts).  
No wiki mainnet entry missing from the tag; no tag mainnet artifact absent from the wiki.

`v1.7.0` vs `v1.6.0` mainnet artifact delta (what newly entered / changed in the latest finalized release):

| Change | Contracts |
|---|---|
| Added | `RegistrarSecurityController`, `RootSecurityController`, `WrappedETHRegistrarController` (artifact present at tag; address is the long-lived controller `0x2535…`) |
| Modified | `RSASHA256Algorithm`, `RSASHA1Algorithm`, `P256SHA256Algorithm` (DNSSEC algorithm replacements) |

This is sufficient to treat **`v1.7.0` as “the latest finalized release deployed to mainnet.”**

### 5. Ethereum mainnet addresses (primary surface)

Full table lives in `research/stage1/mainnet-inventory.md` and `bytecode-correspondence.json`.

High-signal examples:

| Contract | Mainnet address |
|---|---|
| ENSRegistry | `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` |
| BaseRegistrarImplementation | `0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85` |
| ETHRegistrarController | `0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547` |
| WrappedETHRegistrarController | `0x253553366Da8546fC250F225fe3d25d0C782303b` |
| NameWrapper | `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401` |
| PublicResolver | `0xF29100983E058B709F3D539b0c765937B804AC15` |
| UniversalResolver | `0xED73a03F19e8D849E44a39252d222c6ad5217E1e` |
| DNSRegistrar | `0xB32cB5677a7C971689228EC835800432B339bA2B` |
| DNSSECImpl | `0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5` |
| RSASHA256Algorithm | `0xaee0e2c4d5ab2fc164c8b0cc8d3118c1c752c95e` |
| RSASHA1Algorithm | `0x58e0383e21f25dab957f6664240445a514e9f5e8` |
| P256SHA256Algorithm | `0xb091c4f6fac16edda5ee1e0f4738f80011905878` |
| RegistrarSecurityController | `0x7dd4d97653a67c2fd7fba0a84825ec09524d4e1b` |
| RootSecurityController | `0x95123b1ec97df0d3c52c728ab38fbbb7a3ca6da6` |

### 6. Source / bytecode correspondence

Method (2026-08-11):

1. Compare Immunefi wiki address ↔ `v1.7.0` artifact address.
2. `eth_getCode` via `https://1rpc.io/eth` vs artifact `deployedBytecode` where present.
3. Independent Sourcify verification: `https://sourcify.dev/server/v2/contract/1/<address>`.

Results:

| Check | Result |
|---|---|
| Wiki ↔ tag address | **35/35 exact** |
| Sourcify runtime match | **35/35** (`exact_match` or `match`) |
| Raw artifact hex == chain code | 16 exact; 16 differ due to constructor/immutable slots zeroed in artifact but filled on-chain; 3 older artifacts lack bytecode (`ENSRegistry`, `Root`, `BaseRegistrarImplementation`) |

Interpretation: raw hex inequality on immutable-bearing contracts is expected and does **not** by itself indicate a source mismatch. Sourcify `exact_match` / `match` is the binding correspondence check for this checkpoint. See `research/stage1/bytecode-correspondence.json`.

---

## Classification matrix (do not collapse)

| Code / source | Purpose | Bounty posture |
|---|---|---|
| **Latest finalized release `v1.7.0` + mainnet deployment** | Primary bounty target | **In scope** |
| Current `staging` (`55b0eb7` and later) | Historical / current-development reconnaissance | **Not** the mainnet target; useful only for lead generation |
| Older finalized releases (`v1.6.0`, …) | Historical analysis | Out of scope for new mainnet reports unless needed to understand live leftovers |
| Testnet / pre-release (`*-RC*`, `*-testnet`) | Only if Immunefi carve-out is satisfied | Out of scope by default |
| GitHub issues | Leads | Not vulnerabilities |
| Prior audits (Code4rena 2022-07, 2023-04) + Immunefi known issues | Prior knowledge / regression hunting | Not novel findings |

### Why staging must not become the target

Commits on `staging` after `v1.7.0` (recon only):

```
55b0eb7 Update copyright holder in LICENSE.txt (#563)
3b1cc22 Remove "address" from WrappedETHRegistrarController artifact (#551)
eaedc77 Fix `CCIPBatcher._toResponseArray()` (#549)
5787a5f Remove `ICompositeResolver.requiresOffchain()` (#541)
5604925 Add `_toResponseArray()` for safely collapsing multicall responses (#543)
91c966f bump to 1.7.0 (#536)
```

These post-date the latest finalized mainnet release. Findings against them are not automatically bounty-eligible on mainnet.

---

## Open follow-ups (not blockers for Stage 1)

1. Per-contract mapping of which live mainnet bytecode still originates from an older release commit vs was redeployed for `v1.7.0` (important for blame / diff focus).
2. Confirm DNSSECImpl `algorithms(uint8)` currently points at the `v1.7.0` algorithm addresses (governance wiring), not only that the new algorithm contracts exist.
3. Testnet carve-out inventory only if we intentionally pursue RC/testnet work later.
4. Re-run bytecode checks before any report submission; record RPC + block height.

---

## Machine-readable artifacts

- `research/stage1/bytecode-correspondence.json`
- `research/stage1/mainnet-inventory.md`
- `research/stage1/classification.md`

# Stage 2 — .eth Registration / Payment Security Model

**Status:** Attack-surface model (read-only)  
**Date:** 2026-08-11  
**Target:** Git tag `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Method:** `git show v1.7.0:<path>` only — submodule working tree left at `staging` (`55b0eb7`)  
**Focus:** Unprivileged attacker against the .eth registration/payment path  
**Out of scope for findings:** Privileged-only issues unless an escalation path from unprivileged caller exists

---

## 0. Scope map (contracts analyzed)

| Contract | Path @ v1.7.0 | Mainnet (wiki/inventory) | Role |
|---|---|---|---|
| `BaseRegistrarImplementation` | `contracts/ethregistrar/BaseRegistrarImplementation.sol` | `0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85` | ERC721 .eth 2LD registry; expiry / grace / reclaim |
| `ETHRegistrarController` | `contracts/ethregistrar/ETHRegistrarController.sol` | `0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547` | Commit–reveal register + renew + ETH payment |
| `WrappedETHRegistrarController` | **No Solidity source in tag** — only `deployments/mainnet/WrappedETHRegistrarController.json` + deploy script | `0x253553366Da8546fC250F225fe3d25d0C782303b` | Legacy wrapped register path (artifact redeploy) |
| `RegistrarSecurityController` | `contracts/ethregistrar/RegistrarSecurityController.sol` | `0x7dd4d97653a67c2fd7fba0a84825ec09524d4e1b` | Owner of BaseRegistrar; break-glass disable |
| `ExponentialPremiumPriceOracle` | `contracts/ethregistrar/ExponentialPremiumPriceOracle.sol` | `0x7542565191d074cE84fBfA92cAE13AcB84788CA9` | USD rent + post-grace premium |
| `StablePriceOracle` | `contracts/ethregistrar/StablePriceOracle.sol` | (base of premium oracle) | Length-tier rent × ETH/USD |
| `StaticBulkRenewal` | `contracts/ethregistrar/StaticBulkRenewal.sol` | `0xc649947a460B135e6B9a70Ee2FB429aDBB529290` | Batch renew helper |
| `IPriceOracle` | `contracts/ethregistrar/IPriceOracle.sol` | — | `Price{base,premium}` interface |
| `NameWrapper` | `contracts/wrapper/NameWrapper.sol` | `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401` | Wrap / controller-gated `registerAndWrapETH2LD` |
| `ReverseRegistrar` | `contracts/reverseRegistrar/ReverseRegistrar.sol` | (inventory) | `addr.reverse` claims / `setNameForAddr` |
| `DefaultReverseRegistrar` | `contracts/reverseRegistrar/DefaultReverseRegistrar.sol` | (inventory) | Standalone default reverse names |

Deploy wiring (testnets; mainnet uses same roles via governance ops):

- BaseRegistrar **owner** → `RegistrarSecurityController`
- Controllers on BaseRegistrar → `ETHRegistrarController`, `WrappedETHRegistrarController`, `NameWrapper` (via RSC)
- `ETHRegistrarController` also controller on `ReverseRegistrar` + `DefaultReverseRegistrar`
- Commitment ages on controller ctor: `minCommitmentAge = 60`, `maxCommitmentAge = 86400`

---

## 1. Registration state machine

Token id = `uint256(keccak256(bytes(label)))`. Expiry stored in `BaseRegistrar.expiries[id]`.

```
                    ┌─────────────────────────────────────────────────────┐
                    │                                                     │
                    ▼                                                     │
              [UNREGISTERED]                                              │
              expiries[id]==0 OR                                          │
              now > expiry+GRACE                                          │
              available() == true                                         │
                    │                                                     │
                    │ controller.register(id, owner, duration)            │
                    │   expiries = now+duration                           │
                    │   burn if _exists; mint owner                       │
                    │   optional ens.setSubnodeOwner                      │
                    ▼                                                     │
              [ACTIVE]                                                    │
              now < expiry                                                │
              ownerOf(id) OK; ERC721 transfer/reclaim OK                  │
                    │                                                     │
          ┌─────────┴─────────┐                                           │
          │ renew(duration)   │ time passes                               │
          │ expiries += dur   │                                           │
          └─────────┬─────────┘                                           │
                    │                                                     │
                    ▼                                                     │
              [EXPIRED / GRACE]                                           │
              expiry <= now <= expiry+GRACE (90 days)                     │
              available() == false                                        │
              ownerOf() REVERTS                                           │
              transfer / reclaim REVERT (via ownerOf)                     │
              renew() still allowed                                       │
                    │                                                     │
                    │ now > expiry+GRACE                                  │
                    └─────────────────────────────────────────────────────┘
                              → back to UNREGISTERED
                                (NFT may still _exist until re-register burns)
```

### Lifecycle predicates (`BaseRegistrarImplementation`)

| State | `available(id)` | `ownerOf(id)` | `renew` | `reclaim` / ERC721 xfer |
|---|---|---|---|---|
| Never registered / past grace | `true` (`expiry+GRACE < now`) | reverts | reverts (not in grace/active) | reverts |
| Active | `false` | returns owner | OK | OK if approved/owner |
| Grace | `false` | **reverts** | OK | **reverts** |

Constants:

- `GRACE_PERIOD = 90 days` (BaseRegistrar + premium oracle)
- Controller `MIN_REGISTRATION_DURATION = 28 days`
- Overflow guards on `register` / `renew` duration arithmetic

### User-facing path (`ETHRegistrarController`)

```
available(label)  →  commit(commitment)  →  wait ∈ (minAge, maxAge]
        →  register(Registration) payable  →  [ACTIVE]
        →  renew(label, duration, referrer) payable  (anyone may pay)
        →  [EXPIRED/GRACE] → renew OR let lapse → premium auction → register
```

`reclaim(id, owner)` is on BaseRegistrar only: NFT holder (or operator) restores ENS registry owner while name is **active** (not grace).

---

## 2. Public entrypoints and callers

### 2.1 `ETHRegistrarController` (payment gate)

| Function | Visibility | Auth | Notes |
|---|---|---|---|
| `rentPrice(label, duration)` | public view | anyone | Oracle quote |
| `valid(label)` | public pure | anyone | `strlen >= 3` only |
| `available(label)` | public view | anyone | `valid && base.available` |
| `makeCommitment(Registration)` | public pure | anyone | Hashes full struct |
| `commit(bytes32)` | public | anyone | No payment; no msg.sender binding |
| `register(Registration)` | public payable | anyone with valid commitment + payment | Deletes commitment |
| `renew(label, duration, referrer)` | external payable | **anyone** (no ownership check) | Intentional third-party renew |
| `withdraw()` | public | anyone may call; ETH goes to `owner()` | Not theft; grief only if reentered mid-register |
| `recoverFunds` (ERC20Recoverable) | external | `onlyOwner` | Privileged |
| `transferOwnership` / Ownable | | `onlyOwner` | Privileged |
| `supportsInterface` | public view | anyone | |

`Registration` fields committed: `label, owner, duration, secret, resolver, data, reverseRecord, referrer`.

### 2.2 `BaseRegistrarImplementation`

| Function | Auth | Effect |
|---|---|---|
| `addController` / `removeController` | `onlyOwner` (RSC on mainnet) | Gate free mint/renew |
| `setResolver` | `onlyOwner` | `.eth` TLD resolver |
| `register` / `registerOnly` | `live` + `onlyController` | Mint / set expiry; `registerOnly` skips ENS |
| `renew` | `live` + `onlyController` | Extend expiry |
| `reclaim` | `live` + NFT approved/owner | `ens.setSubnodeOwner` |
| ERC721 transfers | standard + custom `_isApprovedOrOwner` using grace-aware `ownerOf` | |
| `ownerOf` / `available` / `nameExpires` | view | |

`live`: `ens.owner(baseNode) == address(this)`.

### 2.3 `RegistrarSecurityController`

| Function | Auth | Effect |
|---|---|---|
| `addRegistrarController` | `onlyOwner` | `registrar.addController` |
| `removeRegistrarController` | `onlyOwner` | revoke |
| `setRegistrarResolver` | `onlyOwner` | |
| `transferRegistrarOwnership` | `onlyOwner` | migrate BaseRegistrar owner |
| `disableRegistrarController` | `onlyController` (security operators) | emergency revoke |
| `setController` (from `Controllable`) | `onlyOwner` | manage security operators |

### 2.4 Price oracles

| Function | Auth | Notes |
|---|---|---|
| `StablePriceOracle.price` / `premium` | view anyone | Immutable rent tiers + Chainlink |
| `ExponentialPremiumPriceOracle._premium` | internal | Post-grace exponential decay |
| `decayedPremium` | public pure | Math helper |

No admin setters on rent/premium after deploy (immutables).

### 2.5 `StaticBulkRenewal` / `BulkRenewal`

| Function | Auth | Notes |
|---|---|---|
| `rentPrice(names[], duration)` | view | Sums `base+premium` (premium normally 0 on renew) |
| `renewAll(names[], duration, referrer)` | payable anyone | Loops `controller.renew{value: base+premium}`; refunds contract balance to `msg.sender` |

`BulkRenewal` resolves controller via `.eth` resolver `interfaceImplementer`; `StaticBulkRenewal` hardcodes controller immutable.

### 2.6 NameWrapper / Reverse (interaction surface)

| Entrypoint | Auth | Relevance to .eth payment path |
|---|---|---|
| `NameWrapper.wrapETH2LD` | NFT owner/operator on BaseRegistrar | Post-register wrap by user |
| `NameWrapper.registerAndWrapETH2LD` | NameWrapper `onlyController` | Used by legacy Wrapped controller |
| `NameWrapper.renew` | NameWrapper `onlyController` | Syncs wrapper expiry |
| `NameWrapper.onERC721Received` | from BaseRegistrar NFT | Wrap-on-transfer |
| `ReverseRegistrar.setNameForAddr` | `authorised(addr)` incl. **controllers** | Called by ETHRegistrarController with `addr = msg.sender` |
| `DefaultReverseRegistrar.setNameForAddr` | `onlyController` | Same |
| `DefaultReverseRegistrar.setName` / signature path | user / signed | Not payment path |

---

## 3. ETH payment / refund logic

### 3.1 Commitments

- `commit` stores `commitments[commitment] = block.timestamp`.
- **No ETH** locked at commit time.
- Rejects if `commitments[c] + maxCommitmentAge >= now` (`UnexpiredCommitmentExists`).
- On successful `register`, commitment is `delete`d before mint side-effects complete (then resolver multicall / reverse / refund).

### 3.2 Rent price

```
price = prices.price(label, base.nameExpires(labelhash), duration)
totalPrice (register) = price.base + price.premium
paid (renew)          = price.base only   // premium ignored on renew path
```

`StablePriceOracle`:

- Character length → immutable atto-USD/second tier → `* duration` → `attoUSDToWei` via `usdOracle.latestAnswer()` (`amount * 1e8 / ethPrice`).
- Controller `valid` requires `strlen >= 3`, so 1–2 letter tiers are unreachable via this controller (still priced in oracle).

`ExponentialPremiumPriceOracle._premium`:

- Premium window starts at `expiry + GRACE_PERIOD`.
- If still in active/grace → premium `0`.
- Else exponential half-life decay from `startPremium` over `totalDays` (deploy: 21), then `premium - endValue` floored at 0.
- Fresh never-registered names (`expires == 0`) have enormous elapsed time → premium decays to 0.

### 3.3 Excess refund

| Path | Requirement | Refund |
|---|---|---|
| `register` | `msg.value >= base+premium` else `InsufficientValue` | `payable(msg.sender).transfer(msg.value - totalPrice)` |
| `renew` | `msg.value >= base` | `transfer` excess over **base** |
| `StaticBulkRenewal.renewAll` | user overpays contract | after loop, `transfer(address(this).balance)` to `msg.sender` |

Refund recipient is always **`msg.sender` of the outer call** (not `Registration.owner`, not referrer).

Uses Solidity `.transfer` (2300 gas). Exact-value calls skip refund.

### 3.4 Premium vs renew mismatch (behavior, not privilege)

- Oracle may return `premium` on quotes; **`renew` only charges `base`**.
- Bulk helpers send `base+premium` into `renew`; excess premium is refunded to the bulk contract then to the user. Economically OK when premium is 0 on renewals.

### 3.5 Proceeds

- Net registration/renewal ETH remains on `ETHRegistrarController`.
- `withdraw()` sends full balance to Ownable `owner()` — callable by anyone (pushes funds to owner).

---

## 4. Interactions with BaseRegistrar, NameWrapper, ReverseRegistrars

### 4.1 `ETHRegistrarController` → BaseRegistrar / ENS

**No resolver (`resolver == 0`):**

1. Require no `data` and no reverse bits (enforced in `makeCommitment`).
2. `base.register(id, registration.owner, duration)` — NFT + ENS owner = `owner`.

**With resolver:**

1. `base.register(id, address(this), duration)` — temporary NFT owner = controller; ENS owner = controller.
2. `ens.setRecord(namehash, owner, resolver, 0)` — ENS owner → user; resolver set; TTL 0.
3. Optional `Resolver(resolver).multicallWithNodeCheck(namehash, data)` — record init.
4. `base.transferFrom(controller, owner, id)` — NFT → user.
5. Optional reverse bits (see below).

Namehash: `keccak256(abi.encodePacked(ETH_NODE, labelhash))` with fixed `.eth` node.

### 4.2 NameWrapper

**Current `ETHRegistrarController` source does not call NameWrapper.** Unwrapped registration only.

Wrapping paths for unprivileged users after register:

- `wrapETH2LD` / `safeTransferFrom` → `onERC721Received` (must own/approve BaseRegistrar NFT).

Legacy **`WrappedETHRegistrarController`** (bytecode artifact, no tag `.sol`):

- Deploy script adds it as BaseRegistrar controller **and** NameWrapper controller.
- Registers via `NameWrapper.registerAndWrapETH2LD` (wrapper calls `registrar.register` to itself, then wraps).

Trust note: `NameWrapper` is itself a BaseRegistrar controller → any NameWrapper controller can mint wrapped names **without** going through ETH payment unless the outer controller enforces payment.

### 4.3 ReverseRegistrar (`addr.reverse`)

On register, if `reverseRecord & 1 != 0`:

```solidity
reverseRegistrar.setNameForAddr(
  msg.sender, msg.sender, registration.resolver,
  string.concat(label, ".eth")
);
```

- Reverse is set for **`msg.sender` (payer/caller)**, **not** `registration.owner`.
- Requires ETHRegistrarController to be ReverseRegistrar controller (deploy does this).
- `PublicResolver` treats `trustedReverseRegistrar` / `trustedETHController` as authorised for `setName` / multicall.

### 4.4 DefaultReverseRegistrar

If `reverseRecord & 2 != 0`:

```solidity
defaultReverseRegistrar.setNameForAddr(msg.sender, string.concat(label, ".eth"));
```

- `onlyController` on DefaultReverseRegistrar.
- Standalone mapping (not ENS registry node).

### 4.5 Custom resolver trust boundary

- Multicall and reverse `setName` succeed on stock `PublicResolver` via trusted addresses.
- User-supplied `registration.resolver` that is **not** a trusting PublicResolver can cause `register` to **revert** (DoS of that registration attempt) or run **arbitrary code** during `multicallWithNodeCheck` (see §8).

---

## 5. Commit–reveal assumptions

### 5.1 Design intent

| Assumption | Mechanism |
|---|---|
| Hide label until reveal window | Commit is `keccak256(abi.encode(Registration))`; only hash on-chain until register |
| Prevent same-block sniping | `commitmentTimestamp + minCommitmentAge > now` → `CommitmentTooNew` |
| Limit stale commits | `+ maxCommitmentAge <= now` → `CommitmentTooOld` / `CommitmentNotFound` |
| Single use | `delete commitments[commitment]` on register |
| Unpredictability | `secret` field in struct (caller-chosen entropy) |

Commitment is **not** bound to committer address: anyone who knows the full `Registration` can `register` after age checks.

### 5.2 Front-running

| Scenario | Outcome for unprivileged attacker |
|---|---|
| Front-run `commit(hash)` with same hash | Attacker owns the stored timestamp; victim `commit` reverts `UnexpiredCommitmentExists`. Attacker **cannot register** without `Registration` fields. **Grief:** blocks that hash until `maxCommitmentAge` (~1 day). |
| Front-run `register(Registration)` with identical calldata | Commitment consumed by attacker; name minted to **`registration.owner`** (victim-chosen). Attacker **pays**; cannot steal name to self without changing `owner` (which changes commitment). **Grief / forced registration** for owner. |
| Front-run register changing `owner` to attacker | Different commitment → fails age/existence checks. **Cannot steal.** |
| Mempool observer learns label from reveal tx | Can race register only with same full struct (same owner/secret/…). |

### 5.3 Replay / reuse

- After successful register: commitment gone; replay needs new `commit` after name again `available` (and new payment).
- After `maxCommitmentAge` without register: same hash may be committed again.
- Same `Registration` (same secret) always same commitment — reuse across attempts is by design; must re-commit after expiry of previous commit slot.

### 5.4 Weak / leaked secret

- If `secret` and other fields are predictable, an observer can compute the commitment early, squat-commit, or prepare to complete register.
- `secret` is **not** verified beyond inclusion in the hash (no separate reveal check).

### 5.5 Availability during reveal

`register` also requires `_available` at reveal time. If name becomes unavailable (someone else registered via another controller path, or grace not ended), register reverts `NameNotAvailable` after payment check — **ETH not taken** on revert (full tx revert). Order: payment check → availability → commitment checks → delete → mint. On revert before completion, no state/ETH kept.

---

## 6. Controllers, ownership, security controller

```
Root / .eth ownership
        │
        ▼
BaseRegistrarImplementation  (ens.owner(ETH_NODE) must be this for live)
        │ owner
        ▼
RegistrarSecurityController
        │ onlyOwner: add/remove registrar controllers, setResolver, transferRegistrarOwnership
        │ onlyController (security ops): disableRegistrarController
        │
        ├── ETHRegistrarController      (payment + commit/reveal)
        ├── WrappedETHRegistrarController (legacy wrapped payment; artifact)
        └── NameWrapper                 (registerAndWrapETH2LD for its controllers)

ETHRegistrarController owner: withdraw / ERC20 recover / Ownable
ReverseRegistrar / DefaultReverseRegistrar: ETHRegistrarController as Controllable controller
NameWrapper controllers: WrappedETHRegistrarController (legacy)
```

**Critical trust boundary:** Any BaseRegistrar `controllers[addr]==true` can call `register` / `renew` / `registerOnly` **with zero ETH**. Payment enforcement exists only in registrar controllers that wrap those calls. Compromised or malicious extra controller = free .eth mint (privileged / misconfig — escalate only if unprivileged can become controller).

**Security controller role:** Emergency `disableRegistrarController` without RSC owner — reduces damage from buggy/malicious payment controller; cannot itself register names unless also added as BaseRegistrar controller (it is not, by design).

**Ownership transfers:** RSC `transferRegistrarOwnership` moves BaseRegistrar Ownable; does not by itself move `.eth` ENS node (still BaseRegistrar if unchanged).

---

## 7. `msg.value` assumptions and refund recipient

| Assumption | Reality in code |
|---|---|
| Caller overpays safely | Excess returned via `.transfer` to **`msg.sender`** |
| Owner receives domain, payer may differ | Yes: `Registration.owner` vs `msg.sender` payer/refund/reverse |
| Referrer receives fee | **No** — `referrer` is event metadata only |
| Smart-contract registrants | If `msg.value > total` and `msg.sender` is a contract whose fallback needs >2300 gas, **refund reverts → whole register/renew reverts**. Exact payment works |
| Bulk renew | User sends ETH to StaticBulkRenewal; inner renew refunds excess to bulk contract; final sweep to user |
| Reentrancy on refund | `.transfer` limits gas; primary reentrancy surface is **resolver multicall before refund** (§8) |
| Oracle priced in ETH | Payment is native ETH only; no ERC20 rent path |
| `withdraw` access | Anyone triggers send-to-owner; cannot redirect |

---

## 8. Candidate invariants and high-risk trust boundaries

### 8.1 Candidate invariants (for testing / formalization)

1. **Payment ↔ mint:** A name minted via `ETHRegistrarController.register` increases controller ETH balance by exactly `base+premium` (net of refunds), except owner `withdraw`.
2. **Commitment single-use:** Successful register ⇒ `commitments[c] == 0`.
3. **Commitment window:** Register succeeds only if `minAge < now - ts <= maxAge` (strict inequalities per code).
4. **Availability:** `register` on BaseRegistrar requires `available(id)`; controller additionally `strlen >= 3`.
5. **Owner binding:** Final ERC721 owner and (with resolver path) ENS owner equal `Registration.owner` after successful register (NFT transferred; ENS set via `setRecord`).
6. **No premium on renew charge:** `renew` reduces controller balance increase to `price.base` only.
7. **Grace protection:** While in grace, `ownerOf` reverts ⇒ no ERC721 transfer/reclaim; `available` false ⇒ no re-register until grace ends.
8. **Reverse targets caller:** Reverse bits mutate `msg.sender` reverse records only, never `Registration.owner`’s (unless equal).
9. **Controller exclusivity:** Non-controllers cannot BaseRegistrar.register/renew.
10. **Live:** If BaseRegistrar loses `.eth` ENS ownership, register/renew/reclaim revert.

### 8.2 High-risk trust boundaries (unprivileged attacker focus)

Keep privileged-only issues out unless escalation exists.

| Boundary | Unprivileged capability | Risk class |
|---|---|---|
| **Commit squat** | Copy commitment hash from mempool; `commit` first | Temporary DoS of that commitment (~`maxCommitmentAge`) |
| **Forced register / fee grief** | Front-run identical `register` | Attacker pays; name still goes to victim `owner`; burns attacker ETH |
| **Resolver multicall reentrancy** | Supply malicious `resolver` + `data` in own registration | During `multicallWithNodeCheck`, arbitrary calls before NFT transfer & refund. Cannot steal others’ names via commitment (deleted/owned). Can attempt nested calls (`withdraw`, other commits, external markets). Primary impact: self-grief, unexpected ETH movement to owner via `withdraw`, integration hazards |
| **PublicResolver trust** | If analyzing custom resolvers | Multicall auth bypass is intentional for `trustedETHController`; custom resolver ≠ free write on PublicResolver without trust |
| **Reverse controller power** | ETHRegistrarController is ReverseRegistrar controller | Unprivileged users only get reverse for `msg.sender` through register bits; **direct** ReverseRegistrar controller APIs are not exposed to random EOAs |
| **Anyone-can-renew** | Pay to extend any name | Not theft; can grief economically by extending enemy names (paid) |
| **Label validity gap** | Labels with `strlen>=3` including `.`, weird Unicode, homographs | Registration of non-normalized labels; phishing / UX — product policy more than classic fund theft |
| **ETH/USD oracle (`latestAnswer`)** | Cannot set feed as unprivileged | If feed returns `0` → div-by-zero revert (DoS pricing). If negative int cast to `uint256` → **price rounds toward 0** → underpayment / free register while oracle broken. **Requires oracle failure** (trust/liveness), not normal user control |
| **Extra BaseRegistrar controllers** | None unless misconfig/compromise | Free mint — privileged/ops; watch for accidental `addController` of untrusted addr |
| **NameWrapper as registrar controller** | Unprivileged cannot call `registerAndWrapETH2LD` | Escalation only if attacker becomes NameWrapper controller |
| **Grace `ownerOf` revert** | Markets/wrappers assuming continuous ownerOf | Integration footgun; known ENS behavior |
| **`.transfer` refund** | Contract wallets overpaying | DoS of overpaying registration for non-receiving contracts |
| **Wrapped controller bytecode-only** | Analyze via artifact/mainnet code, not tag `.sol` | Diff / legacy path may diverge from `ETHRegistrarController` source — separate review surface |

### 8.3 Explicitly de-prioritized (privileged-only, no unprivileged escalation found)

- RSC owner adding malicious controller / transferring BaseRegistrar ownership  
- ETHRegistrarController owner `withdraw` / `recoverFunds` / ownership transfer  
- Security operator `disableRegistrarController`  
- ReverseRegistrar owner `setController` / `setDefaultResolver`  
- Replacing Chainlink feed address (immutable in oracle)

---

## 9. Quick reference — attacker goals vs controls

| Goal | Blocked by | Residual |
|---|---|---|
| Steal name at reveal by changing owner | Commitment binds `owner` | — |
| Register without paying via ETHRegistrarController | `msg.value` check + oracle | Oracle failure → free/cheap |
| Register without commitment | Age / not-found checks | — |
| Reuse spent commitment | `delete` on register | Re-commit after window |
| Snatch name in grace | `available` false until grace ends | Premium auction after grace |
| Transfer during grace | `ownerOf` reverts | Renew still works |
| Redirect refund to self when registering for victim owner | Refund to `msg.sender` only | Attacker must be tx sender |
| Drain controller ETH to self via `withdraw` | Sends to `owner()` | Can only push to owner |

---

## 10. Artifacts / reproducibility

```
Analysis tag:    v1.7.0
Analysis commit: 9b034936a42f462fc04bc0a929a419ede5e18d59
Submodule HEAD:  55b0eb76232f54e3770f1cf778584ba4fa905631 (untouched)
Commands:        git show v1.7.0:contracts/ethregistrar/...
                 git show v1.7.0:contracts/wrapper/NameWrapper.sol
                 git show v1.7.0:contracts/reverseRegistrar/...
                 git show v1.7.0:deploy/ethregistrar/*.ts
```

`WrappedETHRegistrarController.sol` **does not exist** at this tag; use mainnet artifact / Sourcify for that path’s deep dive.

# Stage 2 — Registry / Resolution / Reverse / DNSSEC Security Model

**Status:** Attack-surface model (read-only)  
**Date:** 2026-08-11  
**Target:** Git tag `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Method:** `git show v1.7.0:<path>` only — submodule working tree left at `staging` (`55b0eb7`)  
**Focus:** Unprivileged attacker against registry, resolvers, UniversalResolver/CCIP-read, reverse stack, DNSSEC claim/resolve, multicall  
**Out of scope for findings:** Privileged-only issues unless an escalation path from unprivileged caller exists

---

## 0. Scope map (contracts analyzed)

| Area | Contracts @ v1.7.0 | Role |
|---|---|---|
| Registry | `ENSRegistry`, `ENS` | Node owner / resolver / TTL / operators |
| Root | `Root`, `RootSecurityController`, `Controllable`, `Ownable` (root) | TLD mint lock; break-glass disable |
| Resolvers | `PublicResolver`, `OwnedResolver`, `ResolverBase`, `Multicallable`, profile `*Resolver`s | Record store + auth |
| UniversalResolver | `UniversalResolver`, `AbstractUniversalResolver`, `ResolverCaller`, `RegistryUtils` | ENSIP-10/19 resolution orchestration |
| CCIP | `CCIPReader`, `CCIPBatcher`, `EIP3668`, `GatewayProvider`, `ShuffledGatewayProvider` | OffchainLookup wrap / batch gateway |
| Reverse write | `ReverseRegistrar`, `DefaultReverseRegistrar`, `StandaloneReverseRegistrar`, `SignatureUtils` | Claim / set primary name |
| Reverse read | `AbstractReverseResolver`, `ETHReverseResolver`, `DefaultReverseResolver`, `ChainReverseResolver` | ENSIP-19 reverse resolution |
| DNSSEC claim | `DNSRegistrar`, `DNSClaimChecker`, `PublicSuffixList*` | DNS→ENS ownership |
| DNSSEC oracle | `DNSSECImpl`, `RRUtils`, `RSASHA*`, `P256SHA256`, digests | Proof verification |
| DNS resolve | `OffchainDNSResolver`, `ExtendedDNSResolver` | TXT→resolver / TXT→records |

Mainnet inventory addresses: see `research/stage1/mainnet-inventory.md` (ENSRegistry, PublicResolver, UniversalResolver, Reverse*/DNS*/Root*).

---

## 1. Registry + Root

### 1.1 Public state-changing entrypoints + auth

**`ENSRegistry`**

| Entrypoint | Auth |
|---|---|
| `setOwner(node, owner)` | `authorised(node)`: `records[node].owner == msg.sender` **or** `operators[owner][msg.sender]` |
| `setSubnodeOwner(node, label, owner)` | `authorised(node)` (parent) |
| `setResolver` / `setTTL` | `authorised(node)` |
| `setRecord` / `setSubnodeRecord` | Compose above (owner change then resolver/TTL) |
| `setApprovalForAll(operator, approved)` | Anyone for **self** (`operators[msg.sender][operator]`) |

Notes:

- Constructor sets `records[0x0].owner = msg.sender` (deployer; later Root).
- `owner(node)` returns `address(0)` if stored owner is `address(this)` (burn sentinel).
- `recordExists` ⇔ stored owner ≠ 0.

**`Root`** (must be registry owner of `bytes32(0)`)

| Entrypoint | Auth |
|---|---|
| `setSubnodeOwner(label, owner)` | `onlyController` + `!locked[label]` → `ens.setSubnodeOwner(0, label, owner)` |
| `setResolver(resolver)` | `onlyOwner` → root node resolver |
| `lock(label)` | `onlyOwner` (irreversible in this contract) |
| `setController` | `onlyOwner` (`Controllable`) |

**`RootSecurityController`**

| Entrypoint | Auth |
|---|---|
| `disableTLD(label)` | `onlyOwner` → `root.setSubnodeOwner(label, address(this))` then `ens.setResolver(tldNode, 0)` |

Requires RSC to be a Root **controller**. Break-glass only.

### 1.2 External calls / callbacks

None on registry/root write path (direct storage + ENS calls from Root).

### 1.3 `msg.sender` / ownership assumptions

- Registry auth is **node owner or owner-approved operator**, not signature-based.
- Operators are global per owner address (`ApprovalForAll`), not per-node.
- Root controllers are fully trusted for unlocked TLD assignment.

### 1.4 Trust boundaries

| Conversion | Meaning |
|---|---|
| `node` ↔ owner | Whoever passes `authorised(node)` controls resolver/TTL/subnodes |
| Parent owner → child owner | `setSubnodeOwner` is the only mint path for new labels |
| Root controller → TLD owner | Controllers create TLDs unless `locked` |
| Burn | Owner `address(this)` reads as 0; parent can still overwrite via `setSubnodeOwner` |

### 1.5 Candidate hypotheses (unprivileged)

1. **Operator phishing:** Trick owner into `setApprovalForAll(attacker)` → full registry control of all their nodes.
2. **TLD race via public DNSRegistrar controller:** If DNSRegistrar is a Root controller and suffix list allows a label, anyone calling `DNSRegistrar.enableNode` can cause DNSRegistrar to take that TLD before another intended assignee (ops/race; see §5).
3. **Subnode overwrite:** Parent owner can always seize child — expected hierarchy, not a bug.

### 1.6 KILL list

| Looks scary | Why not bounty-grade (unprivileged) |
|---|---|
| Root owner/controller mint any TLD | Privileged |
| `RootSecurityController.disableTLD` | Privileged owner |
| `lock` irreversible | Privileged intentional |
| Registry has no reentrancy guard | No external calls on write path |
| `owner()==0` via burn sentinel | By design; parent still controls label |

---

## 2. Resolvers (PublicResolver + auth + profiles)

### 2.1 Public state-changing entrypoints + auth

**All profile writers** (`AddrResolver`, `TextResolver`, `ContentHashResolver`, `ABIResolver`, `PubkeyResolver`, `NameResolver`, `DNSResolver`, `DataResolver`, `InterfaceResolver`) gate via `ResolverBase.authorised(node)` → `isAuthorised(node)`.

Also: `clearRecords(node)` bumps `recordVersions[node]` (logical wipe).

**`PublicResolver.isAuthorised(node)`** (OR of):

1. `msg.sender == trustedETHController` (immutable)
2. `msg.sender == trustedReverseRegistrar` (immutable)
3. ENS owner of `node` (if owner is NameWrapper → `nameWrapper.ownerOf(uint256(node))`)
4. PublicResolver operator: `_operatorApprovals[owner][msg.sender]`
5. Per-node delegate: `_tokenApprovals[owner][node][msg.sender]`

**Approval management (unprivileged, self-scoped):**

| Entrypoint | Auth |
|---|---|
| `setApprovalForAll(operator, approved)` | `msg.sender`; cannot self-approve |
| `approve(node, delegate, approved)` | `msg.sender`; cannot self-delegate |

**`OwnedResolver`:** `isAuthorised` ⇒ `msg.sender == owner()` only (no per-node ENS check).

**`Multicallable`:**

| Entrypoint | Behavior |
|---|---|
| `multicall(data[])` | `delegatecall` each payload; **no** node binding |
| `multicallWithNodeCheck(nodehash, data[])` | Same, but each calldata’s bytes `[4:36]` must equal `nodehash` |

Each subcall still runs normal `authorised` (except trusted controller/registrar bypass).

### 2.2 External calls / callbacks

- Profile setters: storage only (events).
- `InterfaceResolver.interfaceImplementer` (view): `staticcall` to `addr(node)` for ERC165.
- `ReverseClaimer` constructor: claims reverse for deployer via ReverseRegistrar (deploy-time only).

No OffchainLookup in PublicResolver itself.

### 2.3 Assumptions

- Trusted controller/registrar may write **any** node without owning it — payment/claim paths must use `multicallWithNodeCheck` so the bound node matches the registered name.
- PublicResolver approvals are **independent** of registry `setApprovalForAll`.
- First ABI arg of multicall subcalls is assumed to be `bytes32 node` for the node-check helper (not enforced for arbitrary selectors).

### 2.4 Trust boundaries

| Conversion | Meaning |
|---|---|
| Registry owner → resolver write | Via `ens.owner` / wrapped ownerOf |
| Operator/delegate → resolver write | PublicResolver-local grants |
| Trusted controller → resolver write | Unconditional; node-check is caller discipline |
| `clearRecords` → version bump | Old versioned records become unreachable |

### 2.5 Candidate hypotheses (unprivileged)

1. **Cross-node multicall without check:** User/attacker calls `multicall` with mixed nodes — each leg still needs auth; no privilege gain. Residual: UX footgun for integrators who confuse with `multicallWithNodeCheck`.
2. **Trusted bypass misuse:** Only exploitable if unprivileged can become / call as `trustedETHController` or `trustedReverseRegistrar` (immutables — no).
3. **Delegate approval phishing:** `approve(node, attacker)` lets attacker change records but not approval set — still name takeover for resolution.
4. **Wrapper owner confusion:** If registry owner is NameWrapper but token burned/unowned oddly, `ownerOf` behavior determines auth (wrapper invariant; test edge cases).

### 2.6 KILL list

| Looks scary | Why kill |
|---|---|
| `trustedETHController` can set any records | Intentional; unprivileged cannot impersonate |
| `delegatecall` in multicall | `msg.sender` preserved; auth still applies |
| `OwnedResolver` owner controls all nodes on that contract | Shared resolver by design |
| Missing revert data on multicall failure | Availability/UX, not theft |
| InterfaceResolver staticcall to addr | View only |

---

## 3. UniversalResolver + CCIP-read

### 3.1 Public entrypoints + auth

All resolution entrypoints are **`view`** (EIP-3668). No auth; anyone may resolve.

| Entrypoint | Notes |
|---|---|
| `resolve(name, data)` | Default batch gateways |
| `resolveWithGateways(name, data, gateways)` | Caller-supplied gateway URLs |
| `resolveWithResolver(resolver, name, data, gateways)` | **Skips registry resolver lookup**; still `_checkResolver` |
| `reverse(lookupAddress, coinType)` / `WithGateways` | ENSIP-19 primary: reverse `name()` then forward `addr` match |
| `findResolver` / `requireResolver` | Registry walk via `RegistryUtils` |
| Callbacks | `resolveCallback`, `reverseNameCallback`, `reverseAddressCallback`, `resolveDirectCallback*`, `resolveBatchCallback` |
| `ccipBatch` / `ccipBatchCallback` | Batch OffchainLookup session (`CCIPBatcher`) |

`UniversalResolver` adds `ReverseClaimer` at deploy (owner claim only).

### 3.2 External calls / OffchainLookup flow

```
resolve*
  → requireResolver / findResolver (ENS registry reads)
  → _callResolver
       ├─ if IERC7996 + (non-multi OR RESOLVE_MULTICALL):
       │     ccipRead(resolver, resolve? call)     // direct ENSIP-22 path
       └─ else:
             ccipRead(this, ccipBatch(createBatch(...)))  // may OffchainLookup → batch gateway
  → callbacks unwrap extended `bytes`, propagate errors, return (result, resolver)
```

**`CCIPReader.ccipRead`:**

- `staticcall` target; if `OffchainLookup` and `p.sender == target`, re-wrap with `sender=address(this)` and `ccipReadCallback`.
- Mismatched `sender` → treated as failure (not wrapped).
- Unsafe legacy targets: gas-capped `staticcall` (`DEFAULT_UNSAFE_CALL_GAS = 50_000`) after EIP-140 detect.

**`CCIPBatcher`:**

- Per-lookup `staticcall`; collect OffchainLookups; revert one batch `OffchainLookup` to `batch.gateways`.
- Callback: `p.sender.staticcall(callback(response, extraData))` — **does not re-check `p.sender == lu.target`** (unlike CCIPReader wrap path).
- Length mismatch → `InvalidBatchGatewayResponse`.

**Reverse path:** `reverseAddressCallback` requires `lookupAddress` equals decoded primary `addr` (ETH: 20-byte pack; else raw bytes) or `ReverseAddressMismatch`.

### 3.3 Assumptions

- Batch / per-resolver gateways are **untrusted**; honesty of result depends on each resolver’s callback verification.
- `resolveWithResolver` is opt-in client trust of supplied resolver address.
- ENSIP-10: nonzero `offset` requires claimed `IExtendedResolver` (unchecked ERC165); else `ResolverNotFound`.
- Feature bit `RESOLVE_MULTICALL` required for direct multicall on extended resolvers.

### 3.4 Trust boundaries

| Conversion | Meaning |
|---|---|
| DNS name → node → registry.resolver | `RegistryUtils.findResolver` (parent fallback) |
| Resolver + calldata → result | Direct or batch CCIP; extended wraps `resolve(name, data)` |
| Offchain HTTP response → authority | Only via resolver callback logic (UR does not verify crypto itself) |
| Reverse name string → primary | Must forward-resolve to same address bytes |
| `extraData` in OffchainLookup | Opaque to UR; rebound through Context / Batch |

### 3.5 Candidate hypotheses (unprivileged)

1. **Batch sender confusion:** Malicious resolver reverts `OffchainLookup` with `sender ≠ target` but still flagged offchain in batcher → gateway fetches attacker URLs → batcher `staticcall`s attacker-chosen `sender.callback`. Impact limited to **resolution of names whose resolver the attacker already controls** (or parent extended resolver). Hunt for cases where an honest parent/extended path can be induced to emit attacker-controlled OffchainLookup params.
2. **ERC165 interface lie:** Resolver claims/denies `IExtendedResolver` / `IERC7996` incorrectly → wrong call shape; typically fail-closed or self-affecting.
3. **`resolveWithResolver` spoof:** Client using this API can be fed arbitrary resolver — **client bug**, not protocol theft.
4. **Reverse primary phishing:** Attacker sets reverse `name()` to a name they control that also `addr`s back to victim (requires victim’s reverse write auth) — classic ENS primary rules; UR correctly checks addr match only.
5. **Multicall reassembly:** Extended unwrap per-leg; error flags; empty → `UnsupportedResolverProfile`. Seek decoding mismatches that accept attacker bytes as success without callback auth (resolver-specific).
6. **Unsafe gas / EIP-140 heuristics:** Mis-detect legacy resolver → OOG or empty flagged; availability, not theft.

### 3.6 KILL list

| Looks scary | Why kill |
|---|---|
| Anyone can call resolve/reverse | View; no state |
| Caller-supplied gateway URLs | EIP-3668 trust model; client chooses |
| CCIPReader identity callback / recursive wrap | Expected architecture |
| ShuffledGatewayProvider randomness | UX/load-balance; not auth |
| HttpError / ResolverError surfaces | Correct failure reporting |
| Parent extended resolver resolves child names | ENSIP-10 by design (parent owner trusted for subtree resolution) |

---

## 4. Reverse registrars + reverse resolvers

### 4.1 Write path — entrypoints + auth

**`ReverseRegistrar`** (owns `addr.reverse` via registry)

| Entrypoint | Auth |
|---|---|
| `claim` / `claimWithResolver` | Implicit `msg.sender` as `addr` |
| `claimForAddr(addr, owner, resolver)` | `authorised(addr)` |
| `setName(name)` | `msg.sender` → claim + `defaultResolver.setName` |
| `setNameForAddr(addr, owner, resolver, name)` | Via `claimForAddr` auth, then `NameResolver(resolver).setName` |
| `setDefaultResolver` | `onlyOwner` |
| `setController` | `onlyOwner` |

`authorised(addr)` iff:

- `addr == msg.sender`, or
- `controllers[msg.sender]`, or
- `ens.isApprovedForAll(addr, msg.sender)`, or
- `Ownable(addr).owner() == msg.sender` (try/catch; contracts only)

**`DefaultReverseRegistrar`** (standalone mapping; not registry)

| Entrypoint | Auth |
|---|---|
| `setName(name)` | `msg.sender` |
| `setNameForAddrWithSignature(addr, expiry, name, sig)` | ERC-191 hash over `(this, selector, addr, expiry, name)` + `SignatureUtils` |
| `setNameForAddr(addr, name)` | `onlyController` |

**`SignatureUtils.validateSignatureWithExpiry`:**

- ERC-6492 suffix → `UniversalSigValidator` at fixed `0x164a…` `isValidSig`
- Else OZ `SignatureChecker.isValidSignatureNow` (ECDSA / ERC-1271 static)
- Require `block.timestamp ≤ expiry ≤ block.timestamp + 1 hours`

### 4.2 Read path — reverse resolvers

**`AbstractReverseResolver.resolve(name, data)`** (extended):

- `name()` if ENSIP-19 reverse name parses to 20-byte addr + matching coinType (default resolver accepts any EVM coin type)
- `addr(60)` / `addr(node, ct)` for reverse **namespace** → returns `chainRegistrar` bytes when coin matches
- Else `UnsupportedResolverProfile`

**`ETHReverseResolver._resolveName`:** first non-empty of:

1. Standalone `addr.reverse` registrar `nameForAddr`
2. Legacy registry resolver `name(node)` (on-chain staticcall, 100k gas, `LibABI.tryDecodeBytes`)
3. `defaultRegistrar.nameForAddr`

**`DefaultReverseResolver`:** standalone default mapping only.

**`ChainReverseResolver`:** Unruggable Gateway proof of L2 `L2ReverseRegistrar` slot `names[addr]`; fallback default registrar. Owner sets `gatewayVerifier` / URLs. `resolveNames` batches.

### 4.3 External calls / OffchainLookup

- ReverseRegistrar → `ens.setSubnodeRecord` + resolver `setName` (PublicResolver trusts registrar).
- Signature path → external UniversalSigValidator (6492 may CREATE2 then revert-undo).
- ChainReverseResolver → `GatewayFetchTarget.fetch` (OffchainLookup / gateway verify).
- ETHReverseResolver → `staticcall` legacy resolver.

### 4.4 Trust boundaries

| Conversion | Meaning |
|---|---|
| Address → `addr.reverse` subnode | `sha3HexAddress` label under `ADDR_REVERSE_NODE` |
| Signature → set default reverse name | Bound to contract address + selector + addr + expiry + name |
| Contract Ownable.owner → claim EOA reverse of contract | Intentional contract-wallet claim |
| L2 storage proof → name string | `gatewayVerifier` trusted for proof checks |
| Multiple reverse sources | First non-empty wins (ETH / Chain) |

### 4.5 Candidate hypotheses (unprivileged)

1. **`ownsContract` spoof:** Fake `owner()` returning attacker on a contract the victim uses as `addr` — only affects that contract’s reverse, and only if attacker is reported owner (by design for Ownable wallets). Seek non-Ownable weird `owner()` that returns attacker for third-party addresses (generally impossible for EOAs).
2. **Signature replay / cross-name:** Message binds name+expiry+addr+contract; replay within ≤1h is idempotent; cannot retarget addr without new sig. Short calldata `<32` on 6492 check reverts (DoS self).
3. **6492 factory side effects during `setNameForAddrWithSignature`:** Validator undoes deploy via revert byte; hunt for effects that survive (should not). ERC-1271 via SignatureChecker is static — no side effects.
4. **PublicResolver trusted registrar sets `name` on reverse node only:** `setNameForAddr` always claims computed reverse node first — cannot point trusted write at arbitrary non-reverse nodes through this path.
5. **ChainReverseResolver gateway:** Forged proofs accepted only if verifier broken; owner can swap verifier (privileged). Unprivileged: none unless verifier bug.
6. **Legacy `name()` decode:** Malicious legacy resolver returns crafted bytes → wrong primary string; forward check in UR still required for verified primary.

### 4.6 KILL list

| Looks scary | Why kill |
|---|---|
| Controllers set reverse for any addr | Privileged (`ETHRegistrarController` etc.) |
| Anyone sets own reverse to any string | By design (no forward proof on write) |
| Claim assigns registry owner of reverse node to chosen `owner` | Caller-authorized for `addr` |
| Default reverse separate from registry | ENSIP-19 intentional |
| `AbstractReverseResolver` returns registrar as `addr` of namespace | Discovery helper, not user address |

---

## 5. DNSSEC (claim oracle + offchain DNS resolution)

### 5.1 Claim path — entrypoints + auth

**`DNSRegistrar`**

| Entrypoint | Auth |
|---|---|
| `proveAndClaim(name, rrsets)` | **Anyone**; owner set to TXT `a=0x…` address |
| `proveAndClaimWithResolver(...)` | Anyone may prove; **`msg.sender` must equal** DNS owner to set resolver/addr |
| `enableNode(domain)` | Anyone; domain must be public suffix; recursively claims missing parents for `address(this)` |
| `setPublicSuffixList` | Root.owner via `onlyOwner` modifier |

`_claim`:

1. `oracle.verifyRRSet(input)` → `(data, inception)`
2. Derive `labelHash` / parent from supplied `name`
3. `enableNode(parent)`
4. Require `serialNumberGte(inception, inceptions[node])`; store inception
5. `DNSClaimChecker.getOwnerAddress(name, data)` must find `_ens.${name}` TXT `a=0x` + 40 hex

### 5.2 Oracle — `DNSSECImpl`

| Entrypoint | Auth |
|---|---|
| `verifyRRSet(input[, now])` | Anyone view; returns last RRSET rdata + inception |
| `setAlgorithm` / `setDigest` | `owner_only` |

Verification highlights:

- Chain from immutable `anchors` DS set through DS/DNSKEY links.
- Time: inception ≤ now ≤ expiration (RFC1982 serial math).
- Signer name must be suffix of RRSET name (`isSubdomainOf`).
- No NSEC/NSEC3; no wildcards (documented).
- Algorithms: RSASHA1/256 via PKCS#1 v1.5 strict padding; P256SHA256 via precompile `0x100`; digests SHA1/SHA256.

### 5.3 Offchain DNS resolution

**`OffchainDNSResolver`**

- `resolve` → always `OffchainLookup` to `gatewayURL` (`IDNSGateway.resolve` TXT).
- `resolveCallback`: verify RRSETs; parse TXT `ENS1 <resolver> [context]`; call ExtendedDNS / Extended / direct.
- Nested OffchainLookup: require `sender == target`; re-wrap; on resume decode inner `extraData` as `(bytes, address)` and callback that address (original target **not** stored separately).

**`ExtendedDNSResolver`**

- Pure parse of context `a[60]=`, `a[coin]=` / `a[eCHAIN]=`, `t[key]=`.
- `_resolveAddr` → `abi.encode(address)` (correct for `addr(bytes32)`).
- `_resolveAddress` → uses `hexToAddress` (20 bytes only) and returns `abi.encode(address)` while underlying profile returns **`bytes`** — encoding mismatch.

### 5.4 Trust boundaries

| Conversion | Meaning |
|---|---|
| DNSSEC RRSIGs → trusted rdata | Oracle crypto + anchors |
| TXT `_ens.name` `a=0x` → ENS owner | Permissionless `proveAndClaim` |
| Public suffix → DNSRegistrar owns suffix node | `enableNode` / Root controller |
| TXT `ENS1` → resolution delegate + context | OffchainDNSResolver |
| Context KV → addr/text | ExtendedDNSResolver (no signatures) |
| Equal inception replay | Allowed until RRSIG expires / newer inception stored |

### 5.5 Candidate hypotheses (unprivileged)

1. **Proof replay / ENS transfer undo:** After DNS claim, ENS `setOwner` to Bob; anyone resubmits **same** valid RRSET while `serialNumberGte(inception, stored)` holds (equality allowed) and RRSIG unexpired → owner reset to TXT address. **DNS-as-source-of-truth design**; treat as KILL unless bounty program scores unauthorized ENS ownership mutation without new DNS control as in-scope grief/theft. Prefer documenting as known property; only elevate if inception comparison was intended strict `>` and equality is a bug vs spec/docs.
2. **Stale TXT after DNS update without re-claim:** Old proof still valid until expiry while `inceptions[node]` unchanged — same as (1).
3. **`enableNode` TLD snatch:** With DNSRegistrar as Root controller + permissive suffix list (`TLDPublicSuffixList` = any 2LD-shaped single label), unprivileged caller can force DNSRegistrar ownership of unlocked TLDs. Ops/config race.
4. **Oracle algorithm/digest mis-verify:** Focus PKCS padding, keytag, DS hash domain-separation, P256 precompile availability/malleability — classic crypto review; DummyAlgorithm must never be live (privileged set).
5. **OffchainDNSResolver nested extraData shape:** Assumes `(bytes, address)`; wrong shape → mis-routed staticcall during resolution. Malicious ENS1 resolver already controls results; prioritize bugs that affect **honest** nested resolvers (wrong/empty resolution).
6. **ExtendedDNSResolver `addr(coinType)` ABI:** Wrong return encoding / 20-byte-only parse → fail-closed under UR unwrap or wrong client decode — correctness/availability.
7. **Name/`data` mismatch:** Claim `name` vs RRSET: owner extraction requires `_ens.+name` match inside verified data — cannot claim `bar` with `foo` proofs.
8. **TXT parse brittleness:** `a=0x` exact; no whitespace; first matching RR wins — footguns, not theft.

### 5.6 KILL list

| Looks scary | Why kill |
|---|---|
| Anyone can `proveAndClaim` for DNS owner | Intentional permissionless import |
| SHA-1 algorithms still present | Crypto agility / legacy zones; not unprivileged forge if anchors+RSA-SHA256 path sound |
| Owner can `setAlgorithm` | Privileged; DummyAlgorithm = ops footgun |
| No NSEC | Documented; cannot prove nonexistence (not needed for positive claim) |
| Gateway URL on OffchainDNSResolver | Untrusted transport; DNSSEC still verified on callback |
| `readTXT` TODO concatenate | Missing multi-string TXT support — availability |

---

## 6. Multicall patterns (resolver + CCIPBatcher)

### 6.1 Surfaces

| Pattern | Where | Privilege interaction |
|---|---|---|
| `multicall(bytes[])` | `Multicallable` / PublicResolver | Per-subcall `isAuthorised`; no node equality |
| `multicallWithNodeCheck` | Same; used by ETHRegistrarController | Forces calldata `[4:36] == node` |
| UR `multicall` detection | `AbstractUniversalResolver` / `ResolverCaller` | Splits to batch legs; optional direct if feature bit |
| `CCIPBatcher.ccipBatch` | Parallel OffchainLookups | View; gateway untrusted |

### 6.2 Hypotheses

1. **Controller without node check:** If a trusted caller used plain `multicall`, it could write other nodes — **privileged caller bug**, not unprivileged.
2. **Node-check bypass via selector whose first word ≠ node:** Cannot grant extra auth; may wrongly pass check if first word coincides with `nodehash` (e.g. approve operator = `address(uint160(node))`) — controller footgun.
3. **Batcher flag handling:** Mis-accepting `FLAG_*` combinations as success for foreign lookups — review when composing with extended unwrap.
4. **Recursive multicall / nested OffchainLookup depth:** Gas / client complexity; not custody theft.

### 6.3 KILL list

| Looks scary | Why kill |
|---|---|
| `delegatecall` self | Standard multicall pattern |
| Disassembling multicall in UR | Needed for CCIP batching |
| Empty response flags | Conservative failure |

---

## 7. Cross-cutting attacker goals vs controls

| Goal | Primary controls | Residual to probe |
|---|---|---|
| Steal registry ownership of others’ nodes | `authorised` owner/operator | Phishing approvals; DNS proof replay (§5.5.1) |
| Overwrite PublicResolver records | `isAuthorised` + trusted immutables | Phishing PR approvals; wrapper ownerOf edges |
| Spoof UniversalResolver result for victim name | Registry resolver + resolver callback crypto | Parent ENSIP-10 resolver; batch sender tricks only if resolver already evil |
| Fake primary name in UR.reverse | Forward `addr` equality | Write access to reverse records |
| Claim DNS name as attacker | DNSSEC verify + TXT address | Crypto bugs in oracle/algorithms |
| Set someone else’s default reverse via sig | SignatureChecker / 6492 + expiry window | 6492/1271 implementation bugs |
| Become Root/DNS/controller | Owner/controller setters | No unprivileged path found |

---

## 8. Explicit global KILL list (scary ≠ bounty)

1. Governance/owner/controller powers (Root, DNSSEC owner, Reverse owner, RSC, gateway verifier owner).
2. ENSIP-10 parent resolver controls child resolution appearance.
3. Permissionless DNS reclaim reflecting TXT `a=0x` (unless equality-replay ruled a spec deviation).
4. EIP-3668 untrusted gateways (without breaking resolver callback auth).
5. Users setting their own reverse string to arbitrary names (no write-time forward check).
6. `resolveWithResolver` trusting caller-supplied resolver.
7. Missing NSEC / wildcard DNSSEC (documented non-goals).
8. View-only resolution returning wrong data for names the attacker already owns.
9. DoS via revert/gas on self-calls, short signatures, overlong batches.
10. Immute trusted controller addresses — compromise is infra, not unprivileged calldata.

---

## 9. Suggested deep-dive order (unprivileged bounty)

1. **DNSSECImpl + RSA/P256 verify** — only path to forge ownership without keys.
2. **DNSRegistrar inception equality + enableNode/Root controller interaction** — ownership mutation races.
3. **CCIPBatcher sender vs target** + OffchainDNSResolver nested callback decoding — wrong resolution for non-malicious nested resolvers.
4. **ExtendedDNSResolver ABI for `addr(uint256)`** — correctness under UR.
5. **SignatureUtils + fixed UniversalSigValidator** — unauthorized `setNameForAddrWithSignature`.
6. **PublicResolver ↔ NameWrapper ownerOf** edge cases on auth.
7. **UniversalResolver reverse/multicall decoding** — accept forged batch bytes as success.

---

## 10. Artifacts / reproducibility

```
Analysis tag:    v1.7.0
Analysis commit: 9b034936a42f462fc04bc0a929a419ede5e18d59
Submodule HEAD:  55b0eb76232f54e3770f1cf778584ba4fa905631 (untouched)
Commands:        git show v1.7.0:contracts/registry/ENSRegistry.sol
                 git show v1.7.0:contracts/root/{Root,RootSecurityController}.sol
                 git show v1.7.0:contracts/resolvers/{PublicResolver,ResolverBase,Multicallable}.sol
                 git show v1.7.0:contracts/resolvers/profiles/*.sol
                 git show v1.7.0:contracts/universalResolver/*.sol
                 git show v1.7.0:contracts/ccipRead/{CCIPReader,CCIPBatcher,EIP3668}.sol
                 git show v1.7.0:contracts/reverseRegistrar/{ReverseRegistrar,DefaultReverseRegistrar,SignatureUtils}.sol
                 git show v1.7.0:contracts/reverseResolver/*.sol
                 git show v1.7.0:contracts/dnsregistrar/{DNSRegistrar,OffchainDNSResolver,DNSClaimChecker}.sol
                 git show v1.7.0:contracts/dnssec-oracle/{DNSSECImpl,RRUtils}.sol
                 git show v1.7.0:contracts/dnssec-oracle/algorithms/*.sol
                 git show v1.7.0:contracts/dnssec-oracle/digests/*.sol
```

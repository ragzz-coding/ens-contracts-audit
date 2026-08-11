# Stage 2 — NameWrapper Security Model

**Status:** Security model (no findings claimed)  
**Date:** 2026-08-11  
**Target:** `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Mainnet:** NameWrapper `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401`  
**Method:** read-only `git show` / `git ls-tree` against tag `v1.7.0` (submodule working tree not checked out)  
**Scope filter:** Kill privileged-admin-only issues unless they enable unprivileged escalation.

---

## 1. File inventory (`contracts/wrapper/` @ v1.7.0)

| Path | Role |
|---|---|
| `contracts/wrapper/NameWrapper.sol` | Core wrapper logic (1090 LOC) |
| `contracts/wrapper/ERC1155Fuse.sol` | ERC1155 + packed owner/fuses/expiry + ERC721-style `approve` |
| `contracts/wrapper/INameWrapper.sol` | Interface + fuse constants |
| `contracts/wrapper/Controllable.sol` | `controllers` map + `onlyController` |
| `contracts/wrapper/INameWrapperUpgrade.sol` | Upgrade sink: `wrapFromUpgrade(...)` |
| `contracts/wrapper/IMetadataService.sol` | `uri(uint256)` |
| `contracts/wrapper/StaticMetadataService.sol` | Static URI impl (deploy helper) |
| `contracts/wrapper/README.md` | Lifecycle / fuse docs (**code wins on conflicts**) |
| `contracts/wrapper/mocks/*`, `test/*` | Test harnesses only |

**Direct dependencies (not under `wrapper/`):**

| Path | Role |
|---|---|
| `contracts/utils/BytesUtils_LEGACY.sol` | DNS `namehash` / `readLabel` used by NameWrapper |
| `contracts/utils/BytesUtils.sol` | keccak helper used by LEGACY |
| `contracts/utils/ERC20Recoverable.sol` | `onlyOwner` ERC20 sweep |
| `contracts/reverseRegistrar/ReverseClaimer.sol` | Constructor-only reverse claim |
| `contracts/registry/ENS.sol` | Registry interface |
| `contracts/ethregistrar/IBaseRegistrar.sol` | .eth registrar interface |

---

## 2. Actors and authority primitives

| Actor | How established | What it unlocks |
|---|---|---|
| **Contract owner** (`Ownable`) | Deployer / transferred ownership | `setController`, `setMetadataService`, `setUpgradeContract`, `recoverFunds`, ownership transfer |
| **Controller** | `controllers[addr]=true` via `setController` (`onlyOwner`) | `registerAndWrapETH2LD`, `renew` |
| **ERC1155 token owner** | Packed in `_tokens[id]` low 160 bits; cleared to 0 when expired **and** `PARENT_CANNOT_CONTROL` burned | Name control via `canModifyName` |
| **ERC1155 operator** | `_operatorApprovals[owner][operator]` via `setApprovalForAll` | Same as owner for `canModifyName` / transfers (`from` side) |
| **Per-token approved** (`approve`) | `_tokenApprovals[id]` | **Not** transfer authority. Used for parent-side `canExtendSubnames` / `extendExpiry` only |
| **Registry owner / operator** | `ens.owner(node)` / `ens.isApprovedForAll` | `wrap` authorization |
| **Registrar owner / operator** | `registrar.ownerOf(labelTokenId)` / `isApprovedForAll` | `wrapETH2LD` authorization; NFT custody during wrap |
| **Anyone** | — | Views; `onERC721Received` if NFT sent from registrar; transfers if already operator/owner |

### Auth helpers (critical)

```text
canModifyName(node, addr):
  getData(node) → (owner, fuses, expiry)
  (owner == addr || isApprovedForAll(owner, addr))
  && !_isETH2LDInGracePeriod(fuses, expiry)

canExtendSubnames(node, addr):   // typically called with PARENT node
  (owner == addr || isApprovedForAll(owner, addr) || getApproved(node) == addr)
  && !_isETH2LDInGracePeriod(fuses, expiry)

onlyTokenOwner(node)  → requires canModifyName(node, msg.sender)
operationAllowed(node, fuseMask) → requires getData.fuses & fuseMask == 0
onlyController → controllers[msg.sender]
onlyOwner → Ownable
```

**Grace freeze (.eth 2LD):** `_isETH2LDInGracePeriod` is true when `IS_DOT_ETH` and `expiry - 90 days < block.timestamp`. During registrar grace (and after wrapper expiry), `canModifyName` / `canExtendSubnames` are false for that .eth 2LD — owner cannot unwrap, set fuses, set records, etc., until renew syncs expiry (or name is re-registered).

**`getData` vs raw storage:** Public `NameWrapper.getData` / `ownerOf` run `_clearOwnerAndFuses`: if `expiry < now`, fuses view as `0`; if also `PARENT_CANNOT_CONTROL`, owner views as `0`. Raw `_tokens` may still hold owner/fuses until rewritten. `renew` intentionally uses `super.getData` to update expired-but-registrar-live names.

---

## 3. Storage model

| Slot / mapping | Contents |
|---|---|
| `_tokens[tokenId]` | `uint256`: `owner(160) \| fuses(32)<<160 \| expiry(64)<<192` |
| `_operatorApprovals[owner][op]` | ERC1155 operator |
| `_tokenApprovals[tokenId]` | ERC721-style single approved (renewal manager) |
| `names[node]` | DNS-encoded name bytes |
| `metadataService` | URI provider |
| `upgradeContract` | Optional upgrade sink |
| `controllers[addr]` | Controller flag (`Controllable`) |
| Immutables | `ens`, `registrar` |
| Constants | `GRACE_PERIOD=90 days`, `ETH_NODE`, `ETH_LABELHASH`, `ROOT_NODE`, `MAX_EXPIRY` |

**tokenId ↔ node:** `tokenId == uint256(node)` where `node = keccak256(parentNode, labelhash)`. No separate mapping — confusion between labelhash (registrar ERC721 id) and namehash (wrapper ERC1155 id) is a standing footgun for integrators and for `.eth` APIs that take `labelhash` vs `node`.

**Constructor seeding:** `ROOT_NODE` and `ETH_NODE` get `owner=0`, fuses=`PARENT_CANNOT_CONTROL|CANNOT_UNWRAP`, `expiry=MAX_EXPIRY`, plus `names` entries. Nobody can `canModifyName` those nodes (owner is 0).

---

## 4. Fuse bit semantics and permanence

Constants from `INameWrapper.sol`:

| Bit | Name | Class | Effect |
|---|---|---|---|
| 0 | `CANNOT_UNWRAP = 1` | Owner | Blocks unwrap / unwrap-via-zero-owner paths; required (with PCC) before other owner fuses |
| 1 | `CANNOT_BURN_FUSES = 2` | Owner | Blocks further fuse burns via `setFuses` (`operationAllowed`) |
| 2 | `CANNOT_TRANSFER = 4` | Owner | Blocks transfers while unexpired |
| 3 | `CANNOT_SET_RESOLVER = 8` | Owner | Blocks `setResolver` / `setRecord` |
| 4 | `CANNOT_SET_TTL = 16` | Owner | Blocks `setTTL` / `setRecord` |
| 5 | `CANNOT_CREATE_SUBDOMAIN = 32` | Owner | Blocks creating **new** subnames when target is expired/empty |
| 6 | `CANNOT_APPROVE = 64` | Owner | Blocks `approve()`; also keeps `_tokenApprovals` across transfers |
| 16 | `PARENT_CANNOT_CONTROL = 1<<16` | Parent | Emancipation; parent cannot replace/burn further child fuses; expiry clears owner |
| 17 | `IS_DOT_ETH = 1<<17` | System | Set only by `_wrapETH2LD`; not user-settable (`USER_SETTABLE_FUSES` clears this bit) |
| 18 | `CAN_EXTEND_EXPIRY = 1<<18` | Parent | Child owner/operator may `extendExpiry` |
| 19–31 | Custom parent fuses | Parent | User-settable parent half except forced system bits |

Masks:

- `PARENT_CONTROLLED_FUSES = 0xFFFF0000`
- `USER_SETTABLE_FUSES = 0xFFFDFFFF` (everything except `IS_DOT_ETH`)
- `CAN_DO_EVERYTHING = 0`

### Permanence rules (enforced in code)

1. **Fuses only increase (OR)** until expiry: `setFuses` / `setChildFuses` / mint merge use `\|`; `_normaliseExpiry` never decreases expiry.
2. **Expiry clears fuse *views*** (`_clearOwnerAndFuses`); emancipated/locked names also clear owner view.
3. **Parent-controlled fuses survive unwrap** in raw storage (`_burn` keeps fuses/expiry with owner=0). Remint in `ERC1155Fuse._mint` re-applies `parentControlledFuses` if `oldExpiry >= block.timestamp` and never shrinks expiry below `oldExpiry`.
4. **`_canFusesBeBurned`:** any non-parent-controlled fuse bits require both `PARENT_CANNOT_CONTROL` and `CANNOT_UNWRAP` already present in the *resulting* fuse word.
5. **`_checkParentFuses`:** burning any `PARENT_CONTROLLED_FUSES` bit requires parent to have `CANNOT_UNWRAP`.
6. **After PCC burned:** `setChildFuses` reverts if `oldFuses | fuses != oldFuses` (no new fuse bits); expiry extension still allowed.
7. **`.eth` 2LDs** always mint with `PARENT_CANNOT_CONTROL | IS_DOT_ETH` (auto-emancipated). Owner-controlled fuses optional at wrap → can go straight to Locked if `CANNOT_UNWRAP` included (via uint16 + required CU/PCC checks).

---

## 5. Expiry / grace period interactions

```text
.eth 2LD wrapper expiry := registrar.nameExpires(labelTokenId) + GRACE_PERIOD (90d)

Timeline:
  [active)[---- grace 90d ----][expired on registrar / burnable]
           ^                    ^
           registrar expiry     wrapper expiry
           canModifyName=false  ownerOf→0 (PCC set)
           transfer blocked     fuses view as 0
```

| Situation | Owner view | Fuses view | Transfer | Modify (`canModifyName`) |
|---|---|---|---|---|
| Unexpired, no PCC | owner | raw fuses | if `!CANNOT_TRANSFER` | yes (owner/op) |
| Unexpired, PCC | owner | raw fuses | if `!CANNOT_TRANSFER` | yes |
| Expired, no PCC | **owner kept** | 0 | allowed (`_beforeTransfer` PCC check) | yes if not .eth-grace logic |
| Expired, PCC | **0** | 0 | blocked | no |
| .eth in grace | owner (until wrapper expiry) | raw until wrapper expiry | blocked (PCC + grace-adjusted expiry) | **no** (`_isETH2LDInGracePeriod`) |

**Renew path:** `renew` (controller) always renews registrar; updates wrapper `_setData` only if `registrar.ownerOf == this` **and** `ens.owner(node) == this`. Uses `super.getData` so grace-expired wrapper rows can be revived without re-wrap.

**Max expiry:** child expiry capped at parent `getData` expiry (`_normaliseExpiry`). For `.eth` 2LD, parent is `ETH_NODE` with `MAX_EXPIRY`, so cap is max; actual expiry still driven by registrar via wrap/renew.

**Non-.eth wrapped with expiry=0:** treated as always expired for fuse views; PCC cannot “stick” on remint until parent extends expiry ≥ now (README warning).

---

## 6. External / public state-changing functions

Legend: **Priv** = privileged (owner/controller) — bounty-deprioritized unless escalation. **CB** = external callback / untrusted contract call.

### 6.1 Privileged / admin (deprioritize)

| Function | Modifier / auth | Storage / external | Notes |
|---|---|---|---|
| `setController(addr, bool)` | `onlyOwner` | `controllers` | Gates register/renew |
| `setMetadataService` | `onlyOwner` | `metadataService` | URI only |
| `setUpgradeContract` | `onlyOwner` | `upgradeContract`; **CB:** `registrar.setApprovalForAll`, `ens.setApprovalForAll` | Grants/revokes operator on registry + registrar to upgrade target. README wrongly lists this as controller-callable — **code is `onlyOwner`**. |
| `recoverFunds` | `onlyOwner` (`ERC20Recoverable`) | ERC20 `transfer` | Does not touch names |
| `Ownable.transferOwnership` / `renounceOwnership` | `onlyOwner` | owner | — |
| `registerAndWrapETH2LD` | `onlyController` | registrar `register`; mint; optional `ens.setResolver` | Trusted controller (e.g. WrappedETHRegistrarController) |
| `renew` | `onlyController` | registrar `renew`; maybe `_setData` | See grace sync |

### 6.2 Unprivileged / user-facing

| Function | Who can call | Auth check | Storage mutated | External calls / CB | Fuse / expiry gates |
|---|---|---|---|---|---|
| `wrapETH2LD(label, wrappedOwner, ownerControlledFuses, resolver)` | Registrar NFT owner or operator | `registrar.ownerOf` / `isApprovedForAll` | `names`, `_tokens` mint | `registrar.transferFrom`, `reclaim`; optional `ens.setResolver`; mint → `onERC1155Received` | Auto `PCC\|IS_DOT_ETH`; CU rules via `_canFusesBeBurned` |
| `onERC721Received(...)` | **Only** `msg.sender == registrar` | Label in `data` must match `tokenId`; NFT already transferred in | same as wrap ETH2LD | `registrar.reclaim`; mint CB | Same as wrapETH2LD |
| `wrap(name, wrappedOwner, resolver)` | Registry owner or operator | `ens.owner` / `isApprovedForAll`; `parentNode != ETH_NODE` | `names[node]`; mint fuses=0,expiry=0 (may inherit PCC) | optional `ens.setResolver`; `ens.setOwner(this)`; mint CB | Parent fuse retention on remint |
| `unwrapETH2LD(labelhash, registrant, controller)` | Token owner/operator | `onlyTokenOwner(ETH_NODE∥labelhash)` | burn token; clear approval | `ens.setOwner`; `registrar.safeTransferFrom` → **ERC721 receiver CB** | `!CANNOT_UNWRAP`; `registrant != this`; grace blocks via `onlyTokenOwner` |
| `unwrap(parentNode, labelhash, controller)` | Token owner/operator | `onlyTokenOwner`; `parentNode != ETH_NODE`; `controller ∉ {0, this}` | burn; `ens.setOwner` | registry only | `!CANNOT_UNWRAP` |
| `setFuses(node, uint16)` | Token owner/operator | `onlyTokenOwner` + `operationAllowed(CANNOT_BURN_FUSES)` | `_tokens` fuses OR | events | Owner half only; CU/PCC required for owner bits |
| `setChildFuses(parent, labelhash, fuses, expiry)` | Parent modifier\* | See below | fuses OR + expiry↑ | events | PCC lock; parent CU for parent bits; must be wrapped (`owner≠0` and `ens.owner==this`) |
| `extendExpiry(parent, labelhash, expiry)` | Parent owner/op/**approved** OR child owner/op | `canExtendSubnames(parent)` **or** (`canModifyName(child)` ∧ `CAN_EXTEND_EXPIRY`) | expiry↑ | event | Must `_isWrapped`; cannot decrease; ≤ parent expiry |
| `setSubnodeOwner(parent, label, owner, fuses, expiry)` | Parent token owner/op | `onlyTokenOwner(parent)` + `_checkCanCallSetSubnodeOwner` | `names`; mint or update; maybe unwrap | `ens.setSubnodeOwner` (create path); transfer CB / unwrap | Parent CU for parent fuses; PCC blocks replace |
| `setSubnodeRecord(...)` | Parent token owner/op | same | same + resolver/ttl | `ens.setSubnodeRecord`; mint/transfer CB | same; note: **no** `operationAllowed(CANNOT_SET_RESOLVER\|TTL)` on parent — parent sets child registry records while replacing/creating |
| `setRecord(node, owner, resolver, ttl)` | Token owner/op | `onlyTokenOwner` + `operationAllowed(CANNOT_TRANSFER\|CANNOT_SET_RESOLVER\|CANNOT_SET_TTL)` | transfer or unwrap | `ens.setRecord(this, resolver, ttl)` then `_transfer` or `_unwrap` | `.eth` cannot unwrap to 0 |
| `setResolver` | Token owner/op | `onlyTokenOwner` + `!CANNOT_SET_RESOLVER` | — | `ens.setResolver` | grace / fuses |
| `setTTL` | Token owner/op | `onlyTokenOwner` + `!CANNOT_SET_TTL` | — | `ens.setTTL` | grace / fuses |
| `approve(to, tokenId)` | Token owner or operator | `!CANNOT_APPROVE`; ERC721 approve rules | `_tokenApprovals` | event | — |
| `setApprovalForAll(op, bool)` | Anyone for self | `msg.sender != op` | `_operatorApprovals` | event | — |
| `safeTransferFrom` / `safeBatchTransferFrom` | `from` or operator (**not** per-token approved) | ERC1155 rules + `_beforeTransfer` | `_tokens` owner; maybe clear approval | `onERC1155(Batch)Received` | `CANNOT_TRANSFER` if unexpired; PCC blocks expired emancipated |
| `upgrade(name, extraData)` | Token owner/op | `canModifyName`; `upgradeContract != 0` | `_burn` | **CB:** `upgradeContract.wrapFromUpgrade(...)` (registry/registrar already approved for upgrade contract if configured) | Burns wrapper token; does not unwrap registry (upgrade target expected to take over via approvals) |

\* **`setChildFuses` auth special case:**

- If `parentNode == ROOT_NODE`: requires `canModifyName(child)` (TLD self-service, including burning parent-controlled fuses because root has `CANNOT_UNWRAP`).
- Else: requires `canModifyName(parentNode)`.
- Consequence: **cannot** call `setChildFuses` with `parent=ETH_NODE` for `.eth` 2LDs — `ETH_NODE` owner is 0. `.eth` owner fuses go through `setFuses` / wrap params only.

### 6.3 `_checkCanCallSetSubnodeOwner` (create vs replace)

```text
expired = subnodeExpiry < now
if expired && (wrapperOwner==0 || ens.owner(subnode)==0):
    // treating as create / reclaim of empty name
    revert if parent has CANNOT_CREATE_SUBDOMAIN
else:
    // replace existing live (or non-empty) name
    revert if child has PARENT_CANNOT_CONTROL
```

Protects emancipated names from parent recreation **while unexpired**, including after unwrap with PCC retained (wrapper owner 0 but ens owner non-zero and unexpired → still PCC-blocked).

---

## 7. Lifecycle transitions (wrap / unwrap / fuses / records)

```text
Unregistered ──register(+wrap)──► Emancipated (.eth) or Wrapped
Unwrapped ──wrap / wrapETH2LD / onERC721Received──► Wrapped | Emancipated | Locked
Wrapped ──setChildFuses(PCC)──► Emancipated
Emancipated ──setFuses(CU) / setChildFuses(CU)──► Locked
Emancipated|Wrapped ──unwrap*──► Unwrapped (PCC bits retained in storage if unexpired)
Locked ──✗ unwrap──► (blocked)
Emancipated|Locked ──expiry──► Unregistered (ownerOf=0; fuses view 0)
Wrapped (no PCC) ──expiry──► still owned; fuses view 0; parent can replace
```

| Entry point | Typical start → end |
|---|---|
| `wrapETH2LD` / `onERC721Received` / `registerAndWrapETH2LD` | Unwrapped/Unregistered → Emancipated (optional Locked if CU burned) |
| `wrap` | Unwrapped → Wrapped (or Emancipated if unexpired PCC retained) |
| `setChildFuses` | Wrapped → Emancipated/Locked; or expiry extend only if already PCC |
| `setFuses` | Emancipated → Locked / more owner locks |
| `setSubnodeOwner/Record` | create Wrapped/Emancipated/Locked child; or transfer; or unwrap if `owner=0` |
| `setRecord(..., owner=0)` | unwrap non-.eth if `!CU` |
| `unwrap` / `unwrapETH2LD` | Emancipated/Wrapped → Unwrapped if `!CU` |
| `renew` | keeps Emancipated/Locked; syncs expiry |
| `extendExpiry` | extends without changing fuse bits |
| `upgrade` | burns local token; migrates via upgrade contract |

**Internal mint merge (`NameWrapper._mint` → `ERC1155Fuse._mint`):** if raw old owner ≠ 0, force-burn + `NameUnwrapped(node, 0)` then remint; parent-controlled fuses OR’d back if old expiry still in future.

**`_updateName` (parent replaces wrapped child):** OR fuses; extend expiry; `owner=0` → `_unwrap`; else `_transfer` (subject to `CANNOT_TRANSFER` / PCC-expiry rules).

---

## 8. External calls and reentrancy surfaces

Ordered by sensitivity for unprivileged callers:

| Site | Call | Untrusted target? | State before call |
|---|---|---|---|
| `_mint` / `_transfer` | `onERC1155Received` / batch | Yes — token recipient | Owner/fuses already written; approvals may be cleared |
| `unwrapETH2LD` | `registrar.safeTransferFrom` → ERC721 receiver | Yes — `registrant` | Token already burned; ens owner already set to `controller` |
| `wrapETH2LD` | `transferFrom` + `reclaim` then mint CB | Registrar trusted; recipient CB after mint | Intermediate: wrapper holds NFT + registry |
| `onERC721Received` | `reclaim` then mint CB | Recipient CB | NFT already here |
| `upgrade` | `upgradeContract.wrapFromUpgrade` | Upgrade impl (owner-set); powerful if malicious | Token burned; upgrade has ens+registrar `setApprovalForAll` |
| `setResolver` / `setTTL` / `setRecord` / wrap paths | ENS registry | Registry trusted | Varies |
| `uri` | `metadataService.uri` | View only | — |

**Notable:** per-token `approve` does **not** grant `safeTransferFrom` rights (ERC1155 operator model). Transfer callbacks therefore require owner/operator collusion or compromised owner key — not “approved renewal manager” alone.

**Reentrancy test artifact:** `contracts/wrapper/test/TestNameWrapperReentrancy.sol`, `NameGriefer.sol` — prior concern around receiver callbacks during wrap/transfer.

---

## 9. Suspicious trust-boundary crossings (hunt list)

These are **invariant / bug-class candidates**, not confirmed issues.

### 9.1 tokenId ↔ node ↔ labelhash

- Wrapper ERC1155 id = `uint256(namehash)`.
- Registrar ERC721 id = `uint256(labelhash)` for `.eth` 2LD only.
- APIs mix both (`unwrapETH2LD(labelhash)`, `renew(tokenId=labelhash)`, `extendExpiry(parent, labelhash)`).
- **Hunt:** any path that treats labelhash as namehash (or vice versa) for auth or burn; mismatched `names[node]` DNS bytes vs actual node.

### 9.2 Parent ↔ child control

- PCC permanence vs parent `setSubnode*` / `setChildFuses` / recreate-after-unwrap.
- `_checkCanCallSetSubnodeOwner` expired∨empty logic vs still-emancipated unexpired unwrapped names.
- Parent `setSubnodeRecord` can change child resolver/ttl without child `CANNOT_SET_*` checks (by design while replace allowed; should be impossible when PCC set).
- `extendExpiry`: parent **approved** can extend any child; child **approved** cannot extend self (only owner/op + `CAN_EXTEND_EXPIRY`).

### 9.3 Fuse permanence / CU / PCC

- Owner fuse burns require PCC|CU in **result** word (`_canFusesBeBurned`).
- Parent fuse burns require parent CU (`_checkParentFuses`).
- Remint re-applies parent half if `oldExpiry >= now` — unwrap must not be a fuse-reset gadget while emancipated.
- Transfer of **expired non-PCC** name uses **view-cleared** fuses from `getData` and writes them via `ERC1155Fuse._setData` — can **persist zero fuses** into storage even if raw bits were non-zero (parent-half retention destroyed by transfer-after-expiry). Confirm intended vs surprise for custom parent fuses.
- `CANNOT_APPROVE` burned ⇒ approvals **survive** transfers (`_beforeTransfer` skips delete).

### 9.4 Owner vs operator vs approved

| Capability | Owner | Operator (`setApprovalForAll`) | Per-token `approve` |
|---|---|---|---|
| Transfer token | yes | yes | **no** |
| `canModifyName` (unwrap, setFuses, setRecord, …) | yes | yes | **no** |
| `extendExpiry` as parent | yes | yes | **yes** |
| `extendExpiry` as child | yes if `CAN_EXTEND_EXPIRY` | yes if fuse | **no** |

**Hunt:** any function that uses the wrong predicate (`getApproved` vs `canModifyName`); operators over-powered equivalent to owners (by design — treat operator as full custody).

### 9.5 Registry / registrar desync (“wrappedness”)

`_isWrapped` / `isWrapped` require wrapper owner ≠ 0 **and** `ens.owner == this` (.eth also `registrar.ownerOf == this`). Direct registry transfers to the wrapper **do not** mint ERC1155 (README).  

**Hunt:** privilege checks that use only one side; `renew` early-exit conditions; unwrap leaving registry/NFT inconsistent; upgrade burn without registry handoff.

### 9.6 Grace period freeze

.eth owner frozen for all `canModifyName` operations in grace, but `renew` (controller) can still sync. Subdomains of a grace-frozen .eth are **not** automatically frozen (parent expiry still `registrar+90d` until wrapper expiry).  

**Hunt:** subdomain guarantees vs parent in grace; whether PCC child can outlive meaningful parent control assumptions.

### 9.7 Upgrade path

Owner sets `upgradeContract` and grants it `setApprovalForAll` on **both** ENS and registrar. User `upgrade()` burns local token then calls sink.  

**Hunt:** unprivileged forced upgrade; sink reentrancy; burning without successful migration; malicious owner upgrade (privileged — deprioritize unless users can be forced).

### 9.8 Callbacks / griefing

Mint/transfer to contracts; `unwrapETH2LD` ERC721 `safeTransferFrom` to attacker registrant; wrap with `wrappedOwner` = griefer contract. Usually self-grief or recipient choice — escalate only if it bricks **another** user’s name or steals custody.

### 9.9 `setRecord` composite fuse mask

Requires **none** of `CANNOT_TRANSFER | CANNOT_SET_RESOLVER | CANNOT_SET_TTL` burned. So a name with only `CANNOT_SET_RESOLVER` cannot use `setRecord` even to change owner/ttl — must use `safeTransferFrom` + `setTTL`. By design; watch for bypass via `setSubnode*` from parent.

---

## 10. Known-invariant candidates

Use these as property tests / manual assertions (bounty-relevant if broken for unprivileged actors):

1. **Custody:** If `isWrapped(parent, labelhash)` then `ens.owner(node) == NameWrapper` (and for `.eth` 2LD, `registrar.ownerOf(labelhash) == NameWrapper`).
2. **tokenId equality:** ERC1155 id for a name always equals `uint256(namehash)`.
3. **PCC non-interference:** While `getData` shows `PCC` and `expiry >= now`, parent cannot change child owner/fuses via `setSubnodeOwner`, `setSubnodeRecord`, or `setChildFuses` (except expiry-only on `setChildFuses`).
4. **CU unwrap ban:** If `CANNOT_UNWRAP` burned and unexpired, `unwrap`, `unwrapETH2LD`, and zero-owner unwrap paths revert.
5. **Owner fuse gating:** No owner-controlled fuse bit can be set unless result also has `PCC|CU` (except pure parent-half operations).
6. **Monotone expiry:** No public function decreases stored expiry.
7. **Emancipated expiry:** If `PCC` and `expiry < now`, `ownerOf` is `0` and transfers fail.
8. **Grace freeze:** If `.eth` 2LD with `expiry - 90d < now`, `canModifyName` is false for all addrs.
9. **Fuse OR-only before expiry:** For unexpired names, fuse bits only flip 0→1.
10. **Approved ≠ owner:** `getApproved(id)` alone never authorizes `safeTransferFrom`, `unwrap*`, `setFuses`, `setRecord`, `setResolver`, `setTTL`, `upgrade`.
11. **IS_DOT_ETH exclusive:** Only `_wrapETH2LD` path sets `IS_DOT_ETH`; `_checkFusesAreSettable` rejects it elsewhere.
12. **ETH_NODE parent ban:** `wrap` / `unwrap` reject `parentNode == ETH_NODE` (must use ETH2LD APIs).
13. **Remint PCC retention:** Unwrap + wrap of unexpired emancipated non-.eth restores `PCC` (and other parent bits) and does not reduce expiry.
14. **Controller isolation:** Non-controllers cannot call `registerAndWrapETH2LD` / `renew`.

---

## 11. README vs code discrepancies (use code)

| Topic | README | Code @ v1.7.0 |
|---|---|---|
| Who calls `setUpgradeContract` | Lists under controllers | `onlyOwner` |
| `INameWrapperUpgrade` | Mentions wrapETH2LD/setSubnodeRecord adaptation | Interface is only `wrapFromUpgrade(...)` |
| Controller powers | register/renew/(upgrade) | **Only** `registerAndWrapETH2LD`, `renew` |

---

## 12. Out-of-scope / deprioritized for bounty

- Contract-owner metadata, controller set, upgrade target, ERC20 recover, ownership transfer — unless an unprivileged user can force them or they permanently seize wrapped names without owner action.
- Honest malicious controller registering names to itself — trusted role (same as registrar controller).
- Metadata URI incorrectness / cosmetic fuse UX.
- Issues only on `staging` (`55b0eb7`) or post-`v1.7.0` commits.

---

## 13. Suggested Stage 2 follow-ups

1. Property-test invariants §10 against Foundry/Hardhat suite at tag `v1.7.0` (local fork).
2. Deep-dive PCC recreate/unwrap edge cases in `_checkCanCallSetSubnodeOwner` with matrix: ens owner × wrapper owner × expiry × PCC.
3. Trace `upgrade()` + hypothetical malicious `upgradeContract` for user-forceable paths (still need unprivileged trigger).
4. Diff NameWrapper vs prior audits (C4 2022-07 / 2023-04) for regression-only leads — do not re-report known issues.
5. Confirm live mainnet controllers on `0xD441…` match WrappedETHRegistrarController / expected set (wiring recon).

---

## Evidence

```bash
# Reproducible reads used for this model
git rev-parse v1.7.0
# → 9b034936a42f462fc04bc0a929a419ede5e18d59
git ls-tree -r --name-only v1.7.0 -- contracts/wrapper/
git show v1.7.0:contracts/wrapper/NameWrapper.sol
git show v1.7.0:contracts/wrapper/ERC1155Fuse.sol
git show v1.7.0:contracts/wrapper/INameWrapper.sol
git show v1.7.0:contracts/wrapper/Controllable.sol
git show v1.7.0:contracts/utils/BytesUtils_LEGACY.sol
```

Submodule working tree left at prior `staging` tip; no checkout performed.

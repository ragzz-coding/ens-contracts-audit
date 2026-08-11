# Stage 2 — High-Risk Mechanism Deep Dive (Phase E summary)

Full function-level detail lives in:

- `NAMEWRAPPER_SECURITY_MODEL.md`
- `REGISTRATION_SECURITY_MODEL.md`
- `RESOLUTION_SECURITY_MODEL.md`

This file indexes state machines and assumptions for hypothesis generation.

---

## 1. NameWrapper

**State:** `_tokens[node] = owner(160)|fuses(32)|expiry(64)`; `names[node]`; approvals; controllers; optional `upgradeContract`.

**Entrypoints (user):** wrap/unwrap, fuse setters, subnode create/replace, record setters, ERC1155 transfer, approve, upgrade.

**Auth:** `canModifyName` / `canExtendSubnames` / `onlyController` / `onlyOwner`.

**External calls:** registrar transfer/reclaim/safeTransferFrom; ens setOwner/setResolver/setSubnode*; ERC1155 receiver; upgrade callback.

**Assumptions:** tokenId≡node; parent expiry cap; PCC permanence until expiry; `.eth` grace = wrapper expiry − 90d.

**Edge cases:** remint parent-fuse retention; expired+PCC owner view 0; approve ≠ transfer; upgrade burns wrapper without unwrap.

## 2. ETHRegistrarController

**State machine:** available → commit → register → active → renew → grace → premium re-register.

**External calls:** BaseRegistrar; ENS setRecord; **user resolver multicallWithNodeCheck**; Reverse registrars; `.transfer` refund.

**Assumptions:** commitment binds all fields; payment ≥ base+premium; trusted resolver node-check if PublicResolver; reverse uses msg.sender.

**Edge cases:** reentrancy in resolver call; commit squat; anyone renew; withdraw to owner; overpay contract-wallet refund DoS.

## 3. BaseRegistrar

**State:** ERC721 + `expiries`; controllers; `live` if owns `.eth`.

**Edge cases:** grace `ownerOf` reverts; register burns preexisting token id; controllers mint unpaid.

## 4. ENS Registry

**Auth:** owner or operator. Parent mint/seize. Burn sentinel `address(this)` reads as 0. No external calls.

## 5. UniversalResolver / CCIP

**View-only** resolution. Batcher callbacks to `OffchainLookup.sender`. Client-supplied gateways. Reverse requires forward addr match.

## 6. PublicResolver / multicall

Trusted controller/reverse bypass. `multicallWithNodeCheck` binds first 32 bytes after selector. Delegatecall preserves msg.sender.

## 7. ReverseRegistrar / DefaultReverseRegistrar

Self/controller/Ownable; signed default reverse with ≤1h expiry; ERC6492 via fixed UniversalSigValidator.

## 8. DNSSEC

`verifyRRSet` → claim TXT owner → `setSubnodeOwner`. Equal inception allowed. Algorithms: RSA PKCS verify (patched), P256 precompile. `enableNode` public-suffix path.

## 9. Offchain DNS resolution

Gateway fetches TXT → ENS1 resolver → optional ExtendedDNS / nested OffchainLookup propagation with extraData reshaping.

## 10. Multicall implementations

PR Multicallable; UR multicall splitting; CCIPBatcher parallel lookups.

## 11. ERC721/1155 transitions

Wrap: 721 to wrapper then 1155 mint+callback. Unwrap: burn 1155 then 721 safeTransfer. Transfers blocked by fuses/grace/PCC+expiry rules.

## 12. Fuses

OR-only; CU+PCC gating; parent-controlled half; IS_DOT_ETH forced on .eth 2LD; CAN_EXTEND_EXPIRY; remint retention.

## 13. Expiry / grace

Registrar 90d grace; wrapper .eth expiry = registrar expiry + 90d; modify frozen in grace; renew syncs.

## 14. Registration / renewal / refund

Commit-reveal; excess to msg.sender; renew base only; bulk renewal helper; proceeds via withdraw→owner.

## 15. Upgrade / proxy machinery in deployment set

No general proxy. NameWrapper `upgradeContract` owner-configured (known DAO issue). Security controllers own registrar/root for emergency ops.

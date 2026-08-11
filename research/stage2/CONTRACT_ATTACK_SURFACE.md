# Stage 2 — Contract Attack Surface

**Target:** ENS `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Method:** read-only `git show` against tag; Stage 1 mainnet inventory  
**Submodule working tree:** left at `staging` / `55b0eb7` (untouched)  
**Companion deep-dives:** `NAMEWRAPPER_SECURITY_MODEL.md`, `REGISTRATION_SECURITY_MODEL.md`, `RESOLUTION_SECURITY_MODEL.md`

---

## 0. In-scope deployed contracts (mainnet)

| Role class | Contract | Mainnet address |
|---|---|---|
| ENS registry | `ENSRegistry` | `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` |
| Root / TLD gate | `Root` | `0xaB528d626EC275E3faD363fF1393A41F581c5897` |
| Root break-glass | `RootSecurityController` | `0x95123b1ec97df0d3c52c728ab38fbbb7a3ca6da6` |
| .eth registrar (ERC721) | `BaseRegistrarImplementation` | `0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85` |
| Registration controller | `ETHRegistrarController` | `0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547` |
| Legacy wrapped controller | `WrappedETHRegistrarController` (**artifact only; no `.sol` in tag**) | `0x253553366Da8546fC250F225fe3d25d0C782303b` |
| Registrar break-glass | `RegistrarSecurityController` | `0x7dd4d97653a67c2fd7fba0a84825ec09524d4e1b` |
| Pricing | `ExponentialPremiumPriceOracle` | `0x7542565191d074cE84fBfA92cAE13AcB84788CA9` |
| Bulk renew | `StaticBulkRenewal` | `0xc649947a460B135e6B9a70Ee2FB429aDBB529290` |
| NameWrapper (ERC1155) | `NameWrapper` | `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401` |
| Metadata | `StaticMetadataService` | `0x3A368e3D5F19aF3DE594A9fC2CFfc6e256a616c7` |
| Resolver | `PublicResolver` | `0xF29100983E058B709F3D539b0c765937B804AC15` |
| Universal resolver | `UniversalResolver` | `0xED73a03F19e8D849E44a39252d222c6ad5217E1e` |
| CCIP batch gateways | `BatchGatewayProvider` | `0xd1E3FAc3837b85437530B8B5244E4deF43219C04` |
| Reverse write | `ReverseRegistrar` | `0xa58E81fe9b61B5c3fE2AFD33CF304c454AbFc7Cb` |
| Default reverse write | `DefaultReverseRegistrar` | `0x283F227c4Bd38ecE252C4Ae7ECE650B0e913f1f9` |
| Reverse read | `DefaultReverseResolver` + chain reverse resolvers | see inventory |
| DNS claim | `DNSRegistrar` | `0xB32cB5677a7C971689228EC835800432B339bA2B` |
| DNSSEC oracle | `DNSSECImpl` | `0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5` |
| DNSSEC algorithms | `RSASHA256Algorithm`, `RSASHA1Algorithm`, `P256SHA256Algorithm` | patched addresses in inventory |
| Digests / suffix lists | `SHA*Digest`, `SimplePublicSuffixList`, `TLDPublicSuffixList` | inventory |
| DNS resolve helpers | `OffchainDNSResolver`, `ExtendedDNSResolver` | inventory |
| Deploy util | `MigrationHelper` | low priority |

**Not upgradeable proxies** in the classical sense: deployments are immutable implementations; “upgrade” for NameWrapper is an optional owner-configured migration sink (`upgradeContract`), not a transparent/UUPS proxy.

---

## 1. Role map (attacker view)

```
                    ┌──────────── Root / RSC ────────────┐
                    │  TLD mint / lock / emergency       │
                    └───────────────┬────────────────────┘
                                    │ owns 0x0
                    ┌───────────────▼────────────────────┐
                    │           ENSRegistry               │
                    │  owner / resolver / TTL / operators  │
                    └───┬───────────────┬────────────┬───┘
           .eth 2LD     │               │            │ DNS TLDs
    ┌───────────────────▼──┐   ┌────────▼─────┐  ┌───▼──────────┐
    │ BaseRegistrar (721)  │   │ NameWrapper  │  │ DNSRegistrar │
    │ expiry / grace       │   │ (1155+fuses) │  │ prove&claim  │
    └──────────┬───────────┘   └──────┬───────┘  └───┬──────────┘
               │ controllers           │              │ oracle
    ┌──────────▼───────────┐           │         ┌────▼─────────┐
    │ ETHRegistrarController│◄──────────┘         │ DNSSECImpl   │
    │ commit/register/renew │   wrapETH2LD        │ + algorithms │
    │ ETH in/out            │                     └──────────────┘
    └──────────┬───────────┘
               │ sets records via
    ┌──────────▼───────────┐     ┌─────────────────────────────┐
    │ PublicResolver       │◄────│ UniversalResolver (view/CCIP)│
    │ + Multicallable      │     │ OffchainDNSResolver         │
    └──────────┬───────────┘     └─────────────────────────────┘
               │
    ┌──────────▼───────────┐
    │ ReverseRegistrar(s)  │
    └──────────────────────┘
```

---

## 2. Per-contract attack surface (security boundaries)

### 2.1 `ENSRegistry` — identity root

| Entrypoint | Caller | Mutates | Boundary |
|---|---|---|---|
| `setOwner` / `setResolver` / `setTTL` / `setRecord` | node owner or owner’s operator | record | **msg.sender → node authority** |
| `setSubnodeOwner` / `setSubnodeRecord` | **parent** owner/operator | child record | **parent → child mint/seize** |
| `setApprovalForAll` | self | operators | global operator grant (phishing surface) |

No ETH. No external calls. Reentrancy not relevant on write path.  
**Security boundary:** whoever is `authorised(node)` can rewrite resolver (resolution hijack) and all subnodes.

### 2.2 `Root` / `RootSecurityController` — TLD gate

Controllers may `setSubnodeOwner` for unlocked labels. RSC owner may disable TLDs.  
**Unprivileged:** none, except if some public contract (e.g. `DNSRegistrar`) is itself a Root controller — then `enableNode` becomes an unprivileged path into Root (see DNS).

### 2.3 `BaseRegistrarImplementation` — .eth NFT + expiry

| Entrypoint | Caller | Boundary |
|---|---|---|
| `register` / `renew` | **controllers only** | free mint/extend — payment must be enforced upstream |
| `reclaim` | NFT owner/operator (active only) | NFT ownership → registry owner |
| ERC721 transfer | owner/operator | grace-aware `ownerOf` (reverts in grace) |

**Assumptions:** `live` ⇔ registrar owns `.eth` node. Grace: transfers/reclaim blocked; renew still allowed via controller.

### 2.4 `ETHRegistrarController` — paid registration (highest ETH surface)

| Entrypoint | Caller | Mutates / moves | Boundary |
|---|---|---|---|
| `commit` | anyone | `commitments[c]=now` | **no msg.sender binding**; squat/grief |
| `register` payable | anyone with valid commitment | deletes commitment; mints via BaseRegistrar; may call **attacker-chosen resolver**; refunds excess to `msg.sender` | **commitment → name ownership**; **msg.value → entitlement**; **temporary controller custody → owner** |
| `renew` payable | **anyone** | extends expiry; refund excess | payment → duration (no ownership check — intentional) |
| `withdraw` | anyone triggers; ETH → `owner()` | drains proceeds | not attacker theft unless owner is wrong |

**Critical call sequence in `register` (resolver path):**

1. Delete commitment  
2. `base.register(id, address(this), duration)` — NFT to controller  
3. `ens.setRecord(namehash, owner, resolver, 0)` — registry to owner  
4. **`Resolver(resolver).multicallWithNodeCheck(namehash, data)`** — **external call to user-supplied address**  
5. `base.transferFrom(this, owner, id)` — NFT to owner  
6. Optional reverse updates for **`msg.sender`** (not `owner`)  
7. Excess refund via `.transfer` (2300 gas)

**Assumptions:** commitment encodes full `Registration`; resolver either respects node-check or is untrusted code; refund recipient is tx sender; reverse bits mutate caller’s reverse, not `owner`’s.

**Reentrancy window:** between steps 4–7, NFT still at controller, ENS owner already `registration.owner`, commitment spent. See hypotheses.

### 2.5 `WrappedETHRegistrarController`

Source **absent** from `v1.7.0` tree; bytecode deployed and listed on wiki. Treat as live controller capable of `NameWrapper.registerAndWrapETH2LD` / renew paths historically. Analyze via artifact ABI + bytecode in later stages if hypotheses require it — do not invent source-level claims.

### 2.6 `NameWrapper` — fuse / wrap authority

Unprivileged high-value entrypoints: `wrapETH2LD`, `onERC721Received`, `wrap`, `unwrap*`, `setFuses`, `setChildFuses`, `extendExpiry`, `setSubnodeOwner`, `setSubnodeRecord`, `setRecord`/`setResolver`/`setTTL`, ERC1155 transfers, `approve` / `setApprovalForAll`, `upgrade` (if configured).

**Boundaries:**

- Registrar NFT owner ↔ wrapper ERC1155 owner (`tokenId == uint256(node)`)
- Parent wrapper authority ↔ child fuses/expiry/ownership  
- Fuse bits ↔ permanent permissions (OR-only until expiry)  
- Grace: `.eth` 2LD `canModifyName` false when `expiry - 90d < now`  
- External callbacks: `onERC1155Received`, `registrar.safeTransferFrom` on unwrap, `upgradeContract.wrapFromUpgrade`

Controllers: `registerAndWrapETH2LD`, `renew` — privileged relative to users.

Owner: `setController`, `setUpgradeContract` (grants registry/registrar approvals to upgrade sink) — **Immunefi known issue if malicious DAO**; do not rediscover.

### 2.7 `PublicResolver` + `Multicallable`

Writers gated by `isAuthorised`: trusted ETH controller **or** trusted reverse registrar **or** ENS/wrapper owner **or** PR operator **or** per-node delegate.

| Entrypoint | Boundary |
|---|---|
| profile setters / `clearRecords` | authorised → record mutation (resolution integrity) |
| `setApprovalForAll` / `approve` | self → operator/delegate (phishing) |
| `multicall` | delegatecall; **no** node binding; each leg still authorised |
| `multicallWithNodeCheck` | forces calldata `[4:36] == node` — **trusted-caller discipline** |

Trusted controller may write any node; safety depends on callers using node-check (ETHRegistrarController does).

### 2.8 `UniversalResolver` / CCIP

Almost entirely `view` + EIP-3668. Attack surface is **resolution integrity**, not direct storage theft.

Boundaries: registry walk → resolver; OffchainLookup → gateway → callback; `CCIPBatcher` invokes `p.sender.callback` (not necessarily `lu.target`); `resolveWithResolver` skips registry (client trust).

### 2.9 Reverse stack

| Contract | Unprivileged writes |
|---|---|
| `ReverseRegistrar` | claim/set for self; controllers; Ownable owner of contract wallets |
| `DefaultReverseRegistrar` | `setName(self)`; `setNameForAddrWithSignature` (ERC-191 + optional ERC6492 via fixed UniversalSigValidator); controllers |

Impact: primary-name integrity / UX phishing; fund misdirection if wallets display reverse as identity.

### 2.10 DNSSEC claim / oracle

| Entrypoint | Boundary |
|---|---|
| `DNSRegistrar.proveAndClaim` | **valid DNSSEC proof + `_ens` TXT `a=0x…` → ENS owner** (permissionless) |
| `proveAndClaimWithResolver` | same + `msg.sender == owner` for resolver set |
| `enableNode` | public for public-suffix domains; may call Root if DNSRegistrar is controller |
| `DNSSECImpl.verifyRRSet` | cryptographic trust root |
| Algorithm contracts | RSA PKCS#1 v1.5 (patched), P256 precompile |

**Inception:** `serialNumberGte(inception, inceptions[node])` allows **equal** inception → replay of same proof resets owner to current TXT (DNS as SoT).

### 2.11 Payment / refund helpers

`StaticBulkRenewal.renewAll`: loops controller renew; refunds contract balance to caller.  
Oracle: Chainlink `latestAnswer` — external dependency (discount / kill for underprice via feed failure per bounty rules).

---

## 3. Composition / callback surfaces (priority)

| Mechanism | Where | Risk type |
|---|---|---|
| User-supplied resolver multicall during register | `ETHRegistrarController` | reentrancy / transient authority |
| ERC721/1155 receiver hooks | wrap/unwrap | reentrancy / ordering |
| NameWrapper upgrade callback | `wrapFromUpgrade` | privileged sink (known DAO issue) |
| `multicall` / `multicallWithNodeCheck` | PublicResolver | auth vs node binding |
| CCIP-read / batch gateway | UniversalResolver, OffchainDNSResolver | resolution integrity |
| DNSSEC verify → setSubnodeOwner | DNSRegistrar | name theft if crypto breaks |
| ERC6492 signature path | DefaultReverseRegistrar | auth bypass if validator wrong |

---

## 4. Explicit deprioritization

- Gas / style / cosmetics  
- Privileged `onlyOwner` / RSC / Root owner actions without escalation  
- Known Immunefi issues (malicious DAO NameWrapper upgrade; DAO expiry reduction; NameWrapper fuse race advisory)  
- Chainlink failure as primary exploit premise  
- Phishing users into `setApprovalForAll` **as the bug itself** (social engineering) — note as user-risk, not protocol vuln unless unexpected approval scope

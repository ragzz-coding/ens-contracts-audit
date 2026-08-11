# Stage 2 — Value / Authority Graph

**Target:** `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`

For every edge: **Can an unprivileged attacker control this value or identity?**

---

## Graph (condensed)

```
ATTACKER
  │
  ├─► commit(commitment)                    [YES: anyone; no identity bind]
  ├─► register(Registration)+ETH            [YES: if commitment exists]
  ├─► renew(label)+ETH                      [YES: anyone can pay]
  ├─► proveAndClaim(dnssec proofs)          [YES: if proofs verify]
  ├─► wrap / unwrap / setFuses / setSubnode*[if owner/operator/approved]
  ├─► resolver record writes                [if authorised]
  ├─► reverse setName / signed setName      [self or valid sig]
  ├─► resolve*() view/CCIP                  [YES: anyone; integrity risk]
  │
  ▼
PUBLIC ENTRYPOINTS
  │
  ▼
ENS CORE
  ├─ ENSRegistry.records[node].{owner,resolver,ttl}
  ├─ operators[owner][op]
  ├─ BaseRegistrar.expiries[id] + ERC721 owner
  ├─ NameWrapper._tokens[node] = owner|fuses|expiry
  ├─ PublicResolver versioned records + approvals
  ├─ commitments[hash]
  ├─ DNSRegistrar.inceptions[node]
  └─ reverse name maps
  │
  ▼
AUTHORITY OBJECTS
  ├─ name ownership (registry owner)
  ├─ NFT ownership (.eth ERC721 / wrapped ERC1155)
  ├─ fuse permissions
  ├─ expiry / grace validity
  ├─ resolver assignment → resolution outputs
  └─ ETH balances (controller proceeds, refunds)
```

---

## Edge analysis (attacker-control questions)

### A. Registration / ETH

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| `commitment` contents | Yes (own) / No (victim’s secret) | Hash binds label, owner, duration, secret, resolver, data, reverse, referrer |
| Who may `commit` | Yes | No committer field → squat |
| Who may `register` | Yes | Pays; owner is whatever commitment says |
| Steal by front-running register | **No name steal** | Same commitment → same owner; attacker only pays |
| Change owner after commit | No | Would change hash |
| `msg.value` → registration | Partially | Must ≥ price; excess refunded to **msg.sender** |
| Redirect payment to attacker | **No** | Proceeds stay on controller until `withdraw` → owner |
| Inflate refund | **No** | refund = msg.value − price |
| Resolver during register | Yes if in commitment | External call; reentrancy window |
| Reverse on register | Yes bits | Sets **msg.sender** reverse, not `owner` |

### B. Ownership / approvals

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| Registry owner of victim node | No (unless parent/DNS/proof) | |
| Registry operator approval | Only if victim grants | Phishing / social — not protocol bug alone |
| ERC721 approval on BaseRegistrar | Only if victim grants | Enables wrapETH2LD / transfer |
| ERC1155 operator on NameWrapper | Only if victim grants | Full modify/transfer |
| Per-token `approve` on NameWrapper | Only if victim grants | **extendExpiry / canExtendSubnames only** — not transfer |
| Parent → child | Yes if attacker owns parent | Expected hierarchy |
| Emancipated child (PCC) | Parent loses replace while unexpired | After expiry, parent can recreate unless `CANNOT_CREATE_SUBDOMAIN` |

### C. Fuses / expiry

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| Burn own fuses | Yes (owner/op) | OR-only; CU+PCC gating |
| Unset burned fuse while live | **No** (intended) | Cleared on expiry view |
| Parent burn child parent-fuses | Yes if parent auth & !PCC lock | |
| Extend expiry beyond parent | **No** | capped |
| `.eth` grace freeze | Time-based | Blocks modify/transfer semantics via grace-adjusted expiry |
| Renew someone else’s .eth | Yes (anyone pays) | Not theft |

### D. Resolution

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| Victim resolver address | No unless own node / approval | |
| Records on PublicResolver | If authorised | |
| UniversalResolver gateways | Caller-supplied on some APIs | Client trust |
| CCIP batch `OffchainLookup.sender` | Set by reverting contract | Malicious resolver can point callback elsewhere |
| Offchain DNS TXT → resolver | If attacker controls DNS or forges DNSSEC | Forge = critical |
| Wrong `addr` returned for victim name | Only via auth bypass / crypto forge / protocol bug | **Fund misdirection impact** |

### E. DNSSEC

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| Submit proofs | Yes | Permissionless |
| Pass `verifyRRSet` without DNS keys | **Must be No** | Else critical name theft |
| TXT `a=0x` owner | Via DNS | DNS SoT |
| Equal-inception replay | Yes | Re-applies same TXT owner — design |
| `enableNode` for public suffix | Yes | May assign DNSRegistrar as TLD owner via Root |

### F. Callbacks / multicall

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| `onERC1155Received` on wrap mint | Yes if recipient is attacker contract | Ordering vs state finality |
| `multicall` mixed nodes | Yes | Each leg needs auth — no free lunch |
| Trusted controller node-check | Controller must pass correct node | ETHRegistrarController does |

### G. Signatures

| Edge | Attacker-controlled? | Notes |
|---|---|---|
| Default reverse ERC-191 | Needs key of `addr` | |
| ERC6492 via UniversalSigValidator | Needs validator to accept | Fixed address `0x164a…`; bypass = high impact |
| Expiry window | ≤ 1 hour future | Replay window bounded |

---

## Value at risk (Immunefi-relevant)

1. **Name ownership** (.eth NFT, registry owner, wrapped token) — Tier 1 systemic if stealable broadly  
2. **Resolution integrity** → payment misdirection  
3. **ETH in controllers** (registration proceeds) — owner-withdraw; attacker redirect?  
4. **DNS-imported names** — crypto forge / claim bugs  
5. **Subdomain / fuse permanence** — parent/child authority surprises  

Non-value (filter): commit grief, anyone-renew, overpay `.transfer` DoS to clumsy contracts, metadata URI.

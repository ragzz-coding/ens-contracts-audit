# Stage 2 — Trust Boundaries

**Target:** `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`

Each row is a representation conversion. Impact column only lists Immunefi-shaped outcomes.

| # | Source | Destination | What proves correspondence? | Attacker influence? | Disagreement possible? | Eligible impact if broken |
|---|---|---|---|---|---|---|
| T01 | `msg.sender` | Registry node owner rights | `records[node].owner` or operator map | Via ownership or phishing approval | Yes if approval broader than user expects | Resolver hijack / subdomain seizure |
| T02 | Registry owner | NameWrapper ERC1155 owner | wrap paths set both; `ens.owner==wrapper` | If wrap auth bypassed | Yes on failed/partial wrap | Name/NFT theft, contradictory ownership |
| T03 | BaseRegistrar ERC721 `labelhash` | ENS node `namehash(.eth ‖ label)` | `reclaim` / register `setSubnodeOwner` | Controller or NFT holder | Yes if reclaim desynced | Registry hijack vs NFT |
| T04 | Wrapper `tokenId` | `bytes32 node` | `tokenId == uint256(node)` convention | Integrator confusion | Mis-aimed calls | Wrong-name ops if UI bugs; protocol uses explicit nodes |
| T05 | Parent node | Child node | `keccak256(parent, labelhash)` + parent auth | Parent owner | Expected seize unless PCC | Subdomain theft from child users |
| T06 | Fuse bits | Permanent permissions | OR burns + PCC/CU gates | Owner/parent per rules | If fuse unset while live | Unauthorized transfer/unwrap/subdomain |
| T07 | Expiry timestamp | Ownership validity | `getData` clearing; registrar grace | Time; renew | Grace vs wrapper +90d mismatch | Premature takeover / frozen control |
| T08 | Commitment hash | Registration entitlement | `keccak256(abi.encode(Registration))` + age | Attacker can register *same* hash | Owner field fixed by hash | Payment grief; not owner theft |
| T09 | `msg.value` | Registration/renewal entitlement | `price` oracle comparison | Overpay/underpay | Refund/revert paths | Payment theft if refund/price wrong |
| T10 | `referrer` bytes32 | (none economically) | Event only | Yes | N/A | None (no fee split) |
| T11 | Temporary controller NFT custody | Final `registration.owner` | `transferFrom` after resolver multicall | Reentrancy during multicall | If transfer skipped/stolen mid-tx | NFT theft |
| T12 | Trusted ETH controller | PublicResolver write auth | immutable trusted address | Must call *as* controller | If spoofed | Arbitrary record writes |
| T13 | Calldata `[4:36]` | Node binding in multicall | `multicallWithNodeCheck` | Craft data | If selector layout ≠ node-first | Cross-node writes by trusted caller |
| T14 | ENS owner | PublicResolver authorised owner | `ens.owner`; if wrapper then `ownerOf` | Wrapper view edge cases | Wrapper/registry desync | Unauthorized record writes |
| T15 | DNSSEC RRSIGs | `verifyRRSet` success | Algorithm verify + DS chain | Forge attempt | Crypto bug | **DNS name theft** |
| T16 | Verified TXT `a=0x` | ENS owner address | `DNSClaimChecker.getOwnerAddress` | DNS content / forge | Parser bugs | Wrong owner assignment |
| T17 | Inception number | Freshness vs `inceptions[node]` | `serialNumberGte` (≥) | Replay equal/newer | Equal replay resets to TXT | Reclaim vs intentional DNS SoT |
| T18 | Offchain gateway response | Resolution result | Resolver callback crypto / DNSSEC verify | Malicious gateway | If callback trusts gateway blindly | Fund misdirection via bad `addr` |
| T19 | `OffchainLookup.sender` | Callback target in batcher | Decoded from revert data | Malicious resolver sets sender | `p.sender` ≠ `lu.target` | Integrity of resolution |
| T20 | ERC-191 / ERC6492 signature | Reverse name for `addr` | `SignatureUtils` + validator | Forged sig | Validator bypass | Reverse identity hijack |
| T21 | Resolver return data | User-perceived address | ABI encoding conventions | Malicious/buggy resolver | ExtendedDNS `abi.encode(address)` vs `bytes` | Mis-decode → misdirection |
| T22 | NameWrapper upgradeContract | Post-upgrade authority | Owner set + approvals | Privileged | Malicious upgrade | **Known issue** — do not rediscover |
| T23 | Chainlink answer | ETH price / rent | Oracle contract | Feed failure | Stale/zero | Pricing DoS/underprice — external dep discount / often OOS |
| T24 | `msg.sender` on register | Reverse record subject | Explicit `setNameForAddr(msg.sender,…)` | Caller | If wrongly used `owner` | Unexpected reverse overwrite |

---

## Boundary clusters to probe experimentally

1. **T11 + I-23** — register resolver reentrancy vs NFT/ETH  
2. **T15–T17** — DNSSEC crypto + claim parser + inception  
3. **T18–T21** — CCIP/OffchainDNS/ExtendedDNS integrity for *honest* names  
4. **T06–T07 + T05** — fuse permanence / expiry recreate semantics (vs known race advisory)  
5. **T20** — ERC6492 reverse auth  

Privileged boundaries (Root owner, RSC, NameWrapper owner upgrade) are documented only to avoid wasting hunt time.

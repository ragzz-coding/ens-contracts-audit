# Stage 2 — Attack Hypotheses (Top 10)

**Target:** `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Filter:** unprivileged, Immunefi-eligible impact, no known-issue duplicates, no governance/oracle/Sybil premises.

Ranking criteria: exploitability × impact × reachability × value × novelty × local-fork PoC ease.

---

## H1 — DNSSEC algorithm verification residual forge

**ID:** H1  
**Title:** Residual cryptographic forge in RSASHA*/P256SHA256 allowing forged RRSIGs  
**Exact contract:** `RSASHA256Algorithm` / `RSASHA1Algorithm` / `P256SHA256Algorithm` (+ `DNSSECImpl.verifyRRSet`)  
**Exact function(s):** `verify`, `verifyRRSet`, `proveAndClaim`  
**Attacker:** Anyone  
**Required initial state:** Victim DNS name importable via DNSRegistrar (public suffix enabled); attacker cannot control real DNS keys  
**Attacker-controlled inputs:** Crafted `DNSSEC.RRSetWithSignature[]`  
**Security boundary crossed:** T15 (RRSIG → verify success)  
**Expected invariant:** I-25  
**How the invariant could fail:** Incomplete PKCS constraints, hash/DigestInfo edge cases, P256 precompile parameter checks, malleability, wrong key parsing lengths allowing false `verify == true`  
**Potential impact:** Steal/claim arbitrary DNS-imported ENS names; set owner to attacker via TXT in forged set  
**Why Immunefi-eligible:** Direct unauthorized name ownership change (Tier 1/2 class-wide for DNS names); critical/high  
**Why unprivileged reachable:** `proveAndClaim` is permissionless  
**Required transaction sequence:** `DNSRegistrar.proveAndClaim(name, forgedProofs)`  
**External dependencies:** None if pure crypto break; DNS SoT not needed  
**Potential blockers:** Patch in `RSAPKCS1Verify` may be complete; P256 precompile may be strict; anchors/DS chain still required  
**Confidence:** Medium (area historically broken; needs dedicated cryptanalysis / differential tests)

## H2 — ETHRegistrarController resolver reentrancy during register

**ID:** H2  
**Title:** Malicious `registration.resolver` reenters during `multicallWithNodeCheck` to desync NFT/ETH/ownership  
**Exact contract:** `ETHRegistrarController`  
**Exact function(s):** `register` → `Resolver.multicallWithNodeCheck`  
**Attacker:** Registrar user who can choose resolver in commitment (or colludes with owner field)  
**Required initial state:** Valid commitment; name available; resolver is attacker contract  
**Attacker-controlled inputs:** `resolver`, `data`, `msg.value`, reentrant calls  
**Security boundary crossed:** T11 (temporary custody → final owner)  
**Expected invariant:** I-13, I-15, I-23  
**How the invariant could fail:** Mid-tx NFT still at controller; ENS already assigned; attacker reenters `withdraw`, second `register`, ERC721 ops, or other controllers to extract NFT or break accounting  
**Potential impact:** NFT/name theft from a registration where `owner` is victim; or theft of pooled registration ETH  
**Why Immunefi-eligible:** Name/NFT theft or direct fund theft  
**Why unprivileged reachable:** Resolver address is user-supplied in public `register`  
**Required transaction sequence:** `commit` → wait → `register` with evil resolver that reenters before `transferFrom`/refund  
**External dependencies:** None  
**Potential blockers:** May only grief self; cannot steal if `owner`≠attacker without separate victim flow; `withdraw` pays controller owner not attacker; commitment deleted already  
**Confidence:** Medium-low for theft; high for needing a decisive PoC kill/confirm

## H3 — OffchainDNSResolver / ExtendedDNSResolver integrity bug mis-resolves honest names

**ID:** H3  
**Title:** Nested OffchainLookup extraData reshaping or ExtendedDNS ABI encoding causes wrong `addr` for DNSSEC-resolved names  
**Exact contract:** `OffchainDNSResolver`, `ExtendedDNSResolver`, consumers via `UniversalResolver`  
**Exact function(s):** `resolveCallback`, `callWithOffchainLookupPropagation`, `ExtendedDNSResolver.resolve`  
**Attacker:** Network attacker controlling DNS gateway responses **or** crafting TXT that passes DNSSEC but confuses parsing; or bug triggered for normal ENS1 records  
**Required initial state:** Name uses OffchainDNSResolver path with ENS1 → ExtendedDNS/nested resolver  
**Attacker-controlled inputs:** Gateway `response` bytes (untrusted transport — crypto should catch); context TXT  
**Security boundary crossed:** T18, T21  
**Expected invariant:** I-27 (ownership unchanged) + resolution correctness for verified records  
**How the invariant could fail:** Nested callback encodes `(targetData, address(this))` assuming inner shape; ExtendedDNS returns `abi.encode(address)` where URI expects `bytes` leading UR/clients to decode attacker-chosen or zero/wrong address  
**Potential impact:** Fund misdirection to wrong address for users resolving affected names  
**Why Immunefi-eligible:** Direct theft/misdirection of user funds in motion (resolution)  
**Why unprivileged reachable:** Permissionless resolve path; if bug hits names following documented ENS1 patterns without attacker owning them, reachability holds. If only attacker-controlled TXT triggers, impact collapses to self-resolution (KILL)  
**Required transaction sequence:** `UniversalResolver.resolve` / offchain follow against forked state with realistic DNS name config  
**External dependencies:** Offchain gateway simulation in tests  
**Potential blockers:** Client ABI expectations may already match; may be known encoding convention  
**Confidence:** Medium

## H4 — CCIPBatcher callback trusts `OffchainLookup.sender` ≠ lookup target

**ID:** H4  
**Title:** Batch callback executes `p.sender.staticcall(callback)` allowing a malicious intermediate to redirect crypto verification  
**Exact contract:** `CCIPBatcher` (via `UniversalResolver`)  
**Exact function(s):** `ccipBatchCallback`  
**Attacker:** Entity that can make an honest resolution path hit a lookup whose OffchainLookup.sender is attacker-controlled **without** owning the name — *or* bug in chaining from OffchainDNSResolver  
**Required initial state:** Resolution uses batch gateway path  
**Attacker-controlled inputs:** OffchainLookup fields inside revert data; batch gateway responses  
**Security boundary crossed:** T19  
**Expected invariant:** I-29  
**How the invariant could fail:** Honest `lu.target` reverts with OffchainLookup{sender: attacker}; batcher calls attacker callback which returns success bytes accepted as resolution data  
**Potential impact:** Wrong resolution result for victim names → fund misdirection  
**Why Immunefi-eligible:** Same as H3 if victim names affected  
**Why unprivileged reachable:** Only if an honest resolver/target can be induced to emit attacker `sender`, or a protocol component does so. If only malicious resolvers (chosen by name owner) are affected → **KILL**  
**Required transaction sequence:** Crafted resolve batch on local fork  
**External dependencies:** Batch gateway mock  
**Potential blockers:** Likely limited to already-untrusted resolvers; may fail reachability filter  
**Confidence:** Low-medium (strong code smell; weak victim-reach story)

## H5 — DefaultReverseRegistrar ERC6492 / SignatureUtils auth bypass

**ID:** H5  
**Title:** Invalid signature accepted via UniversalSigValidator / SignatureChecker path sets reverse for victim `addr`  
**Exact contract:** `DefaultReverseRegistrar`, `SignatureUtils`  
**Exact function(s):** `setNameForAddrWithSignature`, `validateSignatureWithExpiry`  
**Attacker:** Anyone  
**Required initial state:** Victim address (EOA, ERC1271, or counterfactual 6492)  
**Attacker-controlled inputs:** `signature`, `signatureExpiry`, `name`  
**Security boundary crossed:** T20  
**Expected invariant:** I-28  
**How the invariant could fail:** 6492 suffix path incorrectly validates; replay across chain/contracts; message binding missing field; expiry check order issues  
**Potential impact:** Reverse identity hijack; phishing / mis-attribution; secondary fund misdirection in wallets trusting reverse  
**Why Immunefi-eligible:** Borderline — stronger if wallets rely on default reverse for transfers; may triage as medium  
**Why unprivileged reachable:** Public function  
**Required transaction sequence:** Single `setNameForAddrWithSignature` with forged materials  
**External dependencies:** UniversalSigValidator at `0x164af34fAF9879394370C7f09064127C043A35E9`  
**Potential blockers:** OZ SignatureChecker solid for EOAs; 6492 validator battle-tested; impact may be non-critical  
**Confidence:** Low-medium

## H6 — DNSClaimChecker TXT parsing accepts ambiguous owner strings

**ID:** H6  
**Title:** `_ens` TXT parser (`a=0x…`) yields attacker address for records that DNS owners did not intend  
**Exact contract:** `DNSClaimChecker` (library used by `DNSRegistrar._claim`)  
**Exact function(s):** `getOwnerAddress`, `parseString`, `hexToAddress`  
**Attacker:** Anyone submitting proofs for a DNS name whose TXT is weirdly formatted but still signed  
**Required initial state:** DNS zone with crafted TXT still valid under DNSSEC  
**Attacker-controlled inputs:** DNS TXT content (requires DNS control — **often means attacker already DNS-owns the name**)  
**Security boundary crossed:** T16  
**Expected invariant:** I-26  
**How the invariant could fail:** Truncation, whitespace, multiple keys, hex parsing stops early, leading to different address than DNS operator believed  
**Potential impact:** Claim to unexpected owner; if only affects attacker-controlled DNS → weak  
**Why Immunefi-eligible:** Only if third-party DNS configurations commonly used by victims misparse to attacker  
**Why unprivileged reachable:** Weak unless parser reads victim zones incorrectly without attacker DNS control  
**Required transaction sequence:** `proveAndClaim` with real proofs of ambiguous TXT  
**External dependencies:** DNSSEC proofs  
**Potential blockers:** “DNS control required” ≈ attacker already entitled to claim under SoT model → **likely KILL** after PoC attempt  
**Confidence:** Low

## H7 — NameWrapper emancipated child recreate / fuse interaction beyond known advisory

**ID:** H7  
**Title:** Novel unprivileged sequence bypasses PCC / CANNOT_CREATE_SUBDOMAIN protections to seize emancipated subnames before true expiry semantics allow  
**Exact contract:** `NameWrapper`  
**Exact function(s):** `setSubnodeOwner`, `setChildFuses`, `_checkCanCallSetSubnodeOwner`, `_mint` remint  
**Attacker:** Parent owner/operator  
**Required initial state:** Child with PCC burned; parent seeks control early  
**Attacker-controlled inputs:** fuse/expiry parameters; wrap/unwrap interleaving  
**Security boundary crossed:** T05, T06, T07  
**Expected invariant:** I-04, I-06  
**How the invariant could fail:** Expiry/grace/view vs raw storage mismatch; remint parent fuse merge; unwrap+recreate race not covered by known advisory  
**Potential impact:** Subdomain seizure / fuse unset  
**Why Immunefi-eligible:** Name ownership theft for subdomain holders  
**Why unprivileged reachable:** Parent is “unprivileged” relative to protocol but privileged relative to child — still valid attacker if child users trusted emancipation  
**Required transaction sequence:** Multi-step wrap/fuse/time-travel on fork  
**External dependencies:** None  
**Potential blockers:** **High duplicate risk** vs Immunefi known NameWrapper fuse race; must be clearly novel  
**Confidence:** Low-medium pending novelty check

## H8 — PublicResolver authorised ownerOf desync with wrapper burn/expiry views

**ID:** H8  
**Title:** `PublicResolver.isAuthorised` uses `nameWrapper.ownerOf` in a state where registry still points at wrapper but view owner is 0 / transferable wrongly, enabling or blocking writes incorrectly  
**Exact contract:** `PublicResolver`, `NameWrapper`  
**Exact function(s):** `isAuthorised`, `ownerOf` / `getData`  
**Attacker:** Former owner, parent, or stranger depending on desync direction  
**Required initial state:** Wrapped name near expiry / PCC / unwrap mid-states  
**Attacker-controlled inputs:** Timed calls around expiry  
**Security boundary crossed:** T14  
**Expected invariant:** I-16, I-20  
**How the invariant could fail:** Expiry clears owner view while registry owner remains wrapper; writer auth flips unexpectedly  
**Potential impact:** Unauthorized record mutation (resolver hijack) or permanent inability (DoS — weaker)  
**Why Immunefi-eligible:** Resolver hijack → misdirection if writes succeed for attacker  
**Why unprivileged reachable:** If desync grants stranger write — yes; if only owner loses write — weaker  
**Required transaction sequence:** Warp time around wrapper expiry; attempt `setAddr`  
**External dependencies:** None  
**Potential blockers:** May be intentional freeze; need stranger-write for bounty grade  
**Confidence:** Medium-low

## H9 — Commitment/register economic grief that forces victim payment or blocks registration (filtered)

**ID:** H9  
**Title:** Commitment squatting / forced-register payment grief  
**Exact contract:** `ETHRegistrarController`  
**Exact function(s):** `commit`, `register`  
**Attacker:** Anyone observing mempool commitments  
**Required initial state:** Victim committed  
**Attacker-controlled inputs:** Same commitment hash registration  
**Security boundary crossed:** T08  
**Expected invariant:** I-12 (still holds) — owner not stolen  
**How the invariant could fail:** It doesn’t for ownership; attacker can pay for victim’s registration or squat commits  
**Potential impact:** Grief / DoS / economic annoyance  
**Why Immunefi-eligible:** **Likely NO** — not name theft; DoS outside stated impacts  
**Why unprivileged reachable:** Yes  
**Required transaction sequence:** Front-run register or commit  
**External dependencies:** Mempool  
**Potential blockers:** Fails STRICT FILTER (no eligible impact)  
**Confidence:** High that this is a **KILL** — listed to document rejection

## H10 — WrappedETHRegistrarController bytecode-only behavior divergence

**ID:** H10  
**Title:** Live WrappedETHRegistrarController (no source in tag) violates payment/wrap invariants assumed from historical source  
**Exact contract:** `WrappedETHRegistrarController` @ `0x2535…`  
**Exact function(s):** unknown until ABI/bytecode analysis  
**Attacker:** Registrar user of wrapped path  
**Required initial state:** Interacting with legacy wrapped controller still enabled as BaseRegistrar controller  
**Attacker-controlled inputs:** Per ABI  
**Security boundary crossed:** Payment custody / wrap mint authority  
**Expected invariant:** I-11–I-13 analogs for wrapped path  
**How the invariant could fail:** Divergent refund, wrap auth, or controller mint without payment  
**Potential impact:** Name/ETH theft on wrapped registration path  
**Why Immunefi-eligible:** If unpaid mint or theft found  
**Why unprivileged reachable:** Public controller entrypoints if still active  
**Required transaction sequence:** TBD after decompile/ABI from artifact  
**External dependencies:** Artifact ABI  
**Potential blockers:** Path may be deprecated/low traffic; analysis cost high  
**Confidence:** Low (unknown), novelty potentially high

---

## Rejected / killed candidates (explicit)

| Candidate | Why killed |
|---|---|
| Malicious DAO `setUpgradeContract` steals wraps | Immunefi **known issue** + privileged |
| DAO reduces expiries | Known + privileged |
| Classic NameWrapper fuse race as previously advised | Known issue — only novel variants survive as H7 |
| Chainlink underprice registration | External oracle failure / discount |
| Root/RSC disable TLD | Privileged |
| Phishing `setApprovalForAll` | Social engineering |
| Anyone can renew your name | Intentional; costs attacker ETH |
| `withdraw` callable by anyone | Sends to owner, not caller |
| Equal-inception DNS re-claim to TXT owner | DNS source-of-truth design unless strict `>` was specified as security property |
| UniversalResolver caller-chosen gateways lying | Client trust model |
| Gas grief / commit squat alone | No eligible impact (see H9) |

---

## Ranked shortlist for Stage 3

| Rank | ID | Rationale |
|---|---|---|
| 1 | **H1** | Highest impact if true; clear unprivileged path; crypto regressions after recent patch |
| 2 | **H2** | Classic composition bug class; easy local-fork experiment; impact uncertain → prove/kill quickly |
| 3 | **H3** | Resolution→funds misdirection; realistic ENS DNS path; needs careful victim-reach argument |
| 4 | H5 | Cheap to test signatures |
| 5 | H8 | Time-warp fork tests |
| 6 | H4 | Likely kill on reachability |
| 7 | H7 | Duplicate risk |
| 8 | H10 | Bytecode archaeology |
| 9 | H6 | Likely kill |
| 10 | H9 | Documented kill |

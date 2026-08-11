# Stage 3 — Attack Sequences

## H1 — DNSSEC forge (attempted)

**Initial state:** N/A for algorithm-level; conceptually victim DNS-backed ENS name.  
**Attacker:** unprivileged EOA  
**Sequence:**

1. Construct e=3 DNSKEY + Hensel-lifted forged signature over `data=0x00` (same method as ENS regression test).  
2. Call `RSASHA256Algorithm.verify(key, data, forgedSig)`.  
3. Observe `false`.  
4. Contrast: pre-patch harness returns `true` on same inputs.

**State transition:** none on ENS ownership (forge never accepted).

## H2 — Register reentrancy (executed)

**Initial state:** name available; attacker commits `Registration{owner: victim, resolver: EvilResolver, …}`.  
**Attacker:** unprivileged EOA funding `register`.

1. `commit(commitment)`  
2. warp past `minCommitmentAge`  
3. `register{value}(registration)`  
4. During step `multicallWithNodeCheck`, EvilResolver reenters (transferFrom / withdraw / register / setOwner / renew).  
5. Outer transaction completes or reverts.

**Observed final state (successful outer txs):** NFT+ENS owned by **victim**; attacker paid fee; no attacker profit from `withdraw`.

## H3 — Resolution integrity (executed on ExtendedDNS)

**Initial state:** victim context string encoding `a[60]=victim`.  
**Attacker:** calls `ExtendedDNSResolver.resolve` with alternate context.

1. Control: victim context → victim address.  
2. Attack: attacker context → attacker address **only because context arg was attacker-chosen**.  
3. Conclude: not a victim-name compromise without authenticated-context substitution.

**No ENS ownership or registry writes.**

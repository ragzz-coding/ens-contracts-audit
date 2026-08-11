# Stage 2 — History / Security Context

**Current bounty target remains:** `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
Historical material is for **why code exists** and **regression hunting**, not alternate targets.

---

## Release lineage

| Ref | Role |
|---|---|
| `v1.6.0` (`718b1c0…`) | Previous finalized mainnet release |
| commits → `v1.7.0` | ~110 commits including Hardhat v3 migration, security controllers, DNSSEC crypto patch, P256 precompile, UR/CCIP work |
| `v1.7.0` | **In-scope target** |
| `staging` tip `55b0eb7` | Post-release recon only (CCIPBatcher fixes, etc.) — **not bounty target** |

Parent of tag commit: `69f27d2` (UniversalResolver docstring sync) — not a security delta by itself.

---

## Security-meaningful changes landed in / by v1.7.0

| Change | Commit / note | Implication for hunt |
|---|---|---|
| **RSA PKCS#1 v1.5 padding validation** + algorithm redeploys | `c76c5ad` (“Merge commit from fork”) + `RSAPKCS1Verify.sol` | Prior Bleichenbacher-style forge (**CVE-2026-22866**, Immunefi) patched. Hunt for **residual** crypto bugs, not the old missing-padding bug. |
| **P256 → EIP-7951 precompile** | `#509` / same merge | New verify path; check precompile input constraints, malleability, key length checks. |
| `RegistrarSecurityController` / `RootSecurityController` | `e274749`, `0326396` | Break-glass; privileged — not unprivileged targets. |
| ETHRegistrarController without NameWrapper coupling | `e2eaf9b` (“remove wrapper from controller”) | Current paid path is unwrapped register + optional user wrap. |
| CCIPBatcher `FLAG_DONE` / batch behavior | `#499` (`b6cb0e2`); further fixes on staging `#549` | Batching edge cases; staging fixes are **out of target** unless present in `v1.7.0`. |
| ENSIP-24 DataResolver | `#503` (tag tip) | New resolver profile surface on PublicResolver. |
| ShuffledGatewayProvider / ResolverCaller / IERC7996 | `#472`, `#470` | Resolution plumbing. |

---

## Prior audits & known program issues (dedup)

| Item | Use |
|---|---|
| Code4rena 2022-07, 2023-04 | Regression hunting; many NameWrapper fuse/expiry findings historically |
| Immunefi known: malicious DAO NameWrapper upgrade steals names | **Do not rediscover** |
| Immunefi known: malicious DAO reduces expiration | **Do not rediscover** |
| Immunefi known: NameWrapper race — fuses set inappropriately | **Do not rediscover**; still study code to avoid duplicate reports |
| DNSSEC RSA forge (2026) | Patched in tree; verify deployment points DNSSECImpl algorithms at new addresses (Stage 1 inventory matches new algos) |

---

## Diff focus map (`v1.6.0` → `v1.7.0` mainnet artifacts)

From Stage 1:

- New: `RegistrarSecurityController`, `RootSecurityController`, `WrappedETHRegistrarController` artifact entry  
- Changed: `RSASHA*`, `P256SHA256Algorithm` addresses  

Code priorities for regression:

1. DNSSEC verify libraries (new code)  
2. Security controller wiring (privilege only)  
3. UniversalResolver / CCIPBatcher (active development; higher defect density risk)  
4. NameWrapper — relatively stable; still highest historical severity class  
5. ETHRegistrarController payment/resolver ordering  

---

## Strict separation reminder

```
FINDING ON staging-only commit  →  OUT OF SCOPE for mainnet bounty
FINDING ON v1.6.0 only          →  OUT OF SCOPE unless still live bytecode
FINDING ON v1.7.0 live surface  →  IN SCOPE
```

Some live contracts were **not redeployed** for v1.7.0 (e.g. NameWrapper address unchanged). Their **bytecode** is still in scope as part of the latest finalized deployment set; analyze the source as of `v1.7.0` that builds/matches that deployment (Stage 1 Sourcify correspondence).

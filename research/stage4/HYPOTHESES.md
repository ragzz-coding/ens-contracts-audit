# Stage 4 — Hypotheses

| ID | Title | Boundary | Status |
|---|---|---|---|
| S4-H1 | Attacker wrap/seize victim .eth via ownership desync | Registry ↔ Wrapper ↔ NFT | **PROVEN NOT VULNERABLE** |
| S4-H2 | Bypass `CANNOT_TRANSFER` / `CANNOT_UNWRAP` / live PCC / CCS | Fuse enforcement | **PROVEN NOT VULNERABLE** |
| S4-H3 | Unauthorized parent recreate of emancipated child while live | PCC | **PROVEN NOT VULNERABLE** |
| S4-H4 | Parent recreate after emancipated expiry without CCS | Fuse permanence | **PROVEN NOT VULNERABLE** (design; requires missing CCS) |
| S4-H5 | Grace/expiry off-by-one → attacker register or modify | Registrar ↔ Wrapper time | **PROVEN NOT VULNERABLE** |
| S4-H6 | NFT/registry divergence grants stranger control | ERC721 ↔ ENS | **PROVEN NOT VULNERABLE** (lag expected; reclaim gated) |
| S4-H7 | Multicall auth(node A) mutates node B | Resolver auth context | **PROVEN NOT VULNERABLE** |
| S4-H8 | Registry/wrapper operator silently grants PublicResolver write | Approval domains | **PROVEN NOT VULNERABLE** (separate domains) |
| S4-H9 | Stale ERC1155 approval survives transfer | Approval clearing | **PROVEN NOT VULNERABLE** |

No hypothesis elevated to PROVEN VULNERABLE. None left INCONCLUSIVE for the scoped experiments above.

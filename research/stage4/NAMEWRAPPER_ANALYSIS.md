# Stage 4 — NameWrapper Analysis

**Classification of serious hypotheses: PROVEN NOT VULNERABLE** (see POC_RESULTS)

## Ownership confusion (1A)

| Scenario | Result |
|---|---|
| After wrap: registry/wrapper/NFT sync | Enforced — registry & NFT @ wrapper; ERC1155 @ user |
| Attacker wrap of victim NFT | Reverts (`Unauthorised`) |
| Temporary NFT vs registry lag on **unwrapped** ERC721 transfer | **By design** — `reclaim` syncs; only NFT owner/operator can reclaim |

No attacker path found that turns victim-controlled name into attacker effective ownership without receiving the NFT/approval.

## Fuse bypass (1B)

| Fuse / rule | Alternate path attempted | Outcome |
|---|---|---|
| `CANNOT_TRANSFER` | `safeTransferFrom` after burn | Reverts |
| `CANNOT_UNWRAP` | `unwrapETH2LD` | Reverts |
| `PARENT_CANNOT_CONTROL` while live | Parent `setSubnodeOwner` replace | Reverts |
| `CANNOT_CREATE_SUBDOMAIN` | Parent create new child | Reverts |
| Emancipated child after expiry, parent **without** CCS | Parent recreate | **Succeeds — documented design** |
| Emancipated child / any new child, parent **with** CCS | Create/recreate | Reverts |

**Not a vulnerability:** parent recreating an expired emancipated child when `CANNOT_CREATE_SUBDOMAIN` was never burned is intentional fuse semantics (child permanence requires parent CCS).

Duplicate risk vs Immunefi known “fuse race” advisory — no novel bypass demonstrated.

## Expiry / unwrap / rewrap (1C)

| Transition | Outcome |
|---|---|
| Registrar grace (`now > nameExpires`, before +90d) | `canModifyName` false — unwrap/set blocked |
| After wrapper expiry with PCC | `ownerOf` → 0; attacker cannot transfer |
| Unwrap → rewrap | `PCC|IS_DOT_ETH` retained/reapplied; owner restored to wrapper user |
| ERC1155 `approve` then transfer | Approval cleared unless `CANNOT_APPROVE` |

No ownership resurrection or unauthorized reclaim by stranger.

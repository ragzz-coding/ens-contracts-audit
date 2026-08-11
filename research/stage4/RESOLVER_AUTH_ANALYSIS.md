# Stage 4 — Resolver Authorization Analysis

**Harness note:** `PublicResolverAuthHarness` mirrors v1.7.0 `PublicResolver.isAuthorised` + `Multicallable` + `setAddr` only (profiles omitted). Auth predicates match production.

## Authorization model

`isAuthorised(node)` if:

1. `msg.sender` is trusted ETH controller or reverse registrar, else  
2. `owner = ens.owner(node)`; if owner is NameWrapper → `nameWrapper.ownerOf(node)`, then  
3. `msg.sender == owner` OR PublicResolver operator OR per-node delegate.

Registry `setApprovalForAll` ≠ PublicResolver operator. Wrapper ERC1155 operator ≠ PublicResolver operator.

## Multicall / node confusion (3A)

| Attempt | Result |
|---|---|
| `multicall` with setAddr(A) + setAddr(B) where caller only owns A | Reverts on B; B unchanged |
| `multicallWithNodeCheck(A, [setAddr(B,...)])` | Reverts (bytes[4:36] must equal A) |
| Attacker `setAddr` on victim node | Reverts |

No case found where auth evaluates node A while mutating node B successfully.

## Cross-context replay (3B)

No signature-based PublicResolver writes in this surface (reverse signatures are separate; not reopened from Stage 3). Delegate approvals are `(owner, node, delegate)` — node-bound.

## Approval / operator confusion (3C)

| Approval domain | Grants PR write? |
|---|---|
| ENS registry operator | **No** |
| NameWrapper ERC1155 operator | **No** |
| PublicResolver `setApprovalForAll` | **Yes** |
| PublicResolver per-node `approve` | **Yes** (records only) |
| NameWrapper per-token `approve` | extendExpiry path — **not** ERC1155 transfer; cleared on transfer unless `CANNOT_APPROVE` |

Stale wrapper token approval after transfer: cleared (tested).

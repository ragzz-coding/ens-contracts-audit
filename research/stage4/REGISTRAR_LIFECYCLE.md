# Stage 4 — Registrar Lifecycle

## Lifecycle model

```
commit → register → [wrap?] → renew → expire → grace(90d) → available → register
                 ↘ reclaim / ERC721 transfer (active only)
```

Tracked in parallel: BaseRegistrar NFT, ENS registry, NameWrapper ERC1155, expiry, approvals.

## Invariant tested

> For every **live** .eth registration, contracts that represent ownership agree on who has effective authority.

| State | NFT | ENS | Wrapper ERC1155 | Effective authority |
|---|---|---|---|---|
| Unwrapped active | user | user | n/a | NFT owner (+ reclaim) |
| Wrapped active | NameWrapper | NameWrapper | user | Wrapper token owner/operator |
| Grace | `ownerOf` reverts | still set | frozen modify for wrapped | renew via controller; no transfer |
| Past grace | available | stale until re-register | expired | anyone may register (controller) |

## Expiry boundaries (2A)

Deterministic warps at `expiry-1`, `expiry`, `expiry+grace-1`, `expiry+grace+1`:

- Active: `ownerOf` OK  
- Grace: `ownerOf` reverts; `available==false`; register reverts  
- Past grace: `available==true`

No off-by-one allowing attacker register during grace.

## ERC721 / registry divergence (2B)

Unwrapped `transferFrom` without `reclaim` leaves `ens.owner` at previous owner while NFT moved — **expected**. Effective .eth control for registry writes requires reclaim by NFT holder. Not attacker-steal without already receiving NFT.

Wrapped live names: no attacker-induced desync found that grants stranger control.

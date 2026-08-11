# Stage 4 — NameWrapper / Registrar / Resolver State Machine

**Target:** ENS `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Method:** Local Foundry fixture (`local/stage4/foundry`); v1.7.0 contract copies; unprivileged attacker EOAs.

```
UNWRAPPED (.eth NFT @ user, ens.owner = user)
    │ wrapETH2LD / onERC721Received
    ▼
WRAPPED (NFT @ NameWrapper, ens.owner = NameWrapper, ERC1155 @ user)
    │ setSubnodeOwner / setSubnodeRecord
    ▼
SUBDOMAIN CREATED (child ERC1155; optional PCC/CU/expiry)
    │ setFuses / setChildFuses
    ▼
FUSES SET (OR-only while live)
    │ renew / extendExpiry / time
    ▼
EXPIRY CHANGES (grace freeze for .eth; PCC clears owner view when expired)
    │ unwrapETH2LD / unwrap
    ▼
UNWRAP (NFT returned; ens.owner = controller/registrant)
    │ wrap again
    ▼
REWRAP (parent-controlled fuses may remint-retain)
```

## Synchronized fields (live wrapped .eth)

| Representation | Expected |
|---|---|
| BaseRegistrar ERC721 owner | `NameWrapper` |
| ENS Registry owner | `NameWrapper` |
| NameWrapper ERC1155 owner | end-user |
| tokenId | `uint256(namehash)` |
| fuses | includes `IS_DOT_ETH \| PARENT_CANNOT_CONTROL` |
| expiry | `registrar.nameExpires + 90d` |

## Irreversible (while live)

- Burned owner/parent fuses (OR-only until expiry view-clear)
- `CANNOT_UNWRAP` blocks unwrap
- `PARENT_CANNOT_CONTROL` blocks parent replace while child live
- `CANNOT_CREATE_SUBDOMAIN` blocks new/recreate empty children

See experimental results in `POC_RESULTS.md`.

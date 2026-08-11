# Research

Cursor analysis and audit notes for ENS contracts live here.

## Rules

See [`OPERATING_RULES.md`](./OPERATING_RULES.md).

## Stage 1

- [`stage1/BOUNTY_SCOPE.md`](./stage1/BOUNTY_SCOPE.md) — bounty target chain (authoritative)
- [`stage1/classification.md`](./stage1/classification.md) — target vs recon separation
- [`stage1/mainnet-inventory.md`](./stage1/mainnet-inventory.md) — mainnet address inventory @ `v1.7.0`
- [`stage1/bytecode-correspondence.json`](./stage1/bytecode-correspondence.json) — address + Sourcify + raw bytecode checks

**Primary target:** Git tag `v1.7.0` @ commit `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Not the target:** submodule working tree / `staging` tip `55b0eb7`

## Stage 2

- [`stage2/REGISTRATION_SECURITY_MODEL.md`](./stage2/REGISTRATION_SECURITY_MODEL.md) — .eth registration/payment security model (state machine, entrypoints, commit–reveal, payment/refund, trust boundaries)
- [`stage2/RESOLUTION_SECURITY_MODEL.md`](./stage2/RESOLUTION_SECURITY_MODEL.md) — registry / resolvers / UniversalResolver+CCIP / reverse / DNSSEC / multicall attack model (unprivileged)

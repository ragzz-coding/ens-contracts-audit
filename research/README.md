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

Authoritative synthesis:

- [`stage2/CONTRACT_ATTACK_SURFACE.md`](./stage2/CONTRACT_ATTACK_SURFACE.md)
- [`stage2/VALUE_AUTHORITY_GRAPH.md`](./stage2/VALUE_AUTHORITY_GRAPH.md)
- [`stage2/CORE_INVARIANTS.md`](./stage2/CORE_INVARIANTS.md)
- [`stage2/TRUST_BOUNDARIES.md`](./stage2/TRUST_BOUNDARIES.md)
- [`stage2/MECHANISM_DEEP_DIVE.md`](./stage2/MECHANISM_DEEP_DIVE.md)
- [`stage2/HISTORY_SECURITY_CONTEXT.md`](./stage2/HISTORY_SECURITY_CONTEXT.md)
- [`stage2/HYPOTHESES.md`](./stage2/HYPOTHESES.md)
- [`stage2/PHASE_H_VERDICT.md`](./stage2/PHASE_H_VERDICT.md)

Supporting deep models:

- [`stage2/NAMEWRAPPER_SECURITY_MODEL.md`](./stage2/NAMEWRAPPER_SECURITY_MODEL.md)
- [`stage2/REGISTRATION_SECURITY_MODEL.md`](./stage2/REGISTRATION_SECURITY_MODEL.md)
- [`stage2/RESOLUTION_SECURITY_MODEL.md`](./stage2/RESOLUTION_SECURITY_MODEL.md)

**Stage 2 verdict:** PROMISING — strongest tests: H1 (DNSSEC crypto), H2 (register reentrancy), H3 (offchain DNS resolution integrity).

## Stage 3

Experimental validation of H1–H3 (local Foundry harness under `local/stage3/foundry/`):

- [`stage3/H1_DNSSEC_RESULTS.md`](./stage3/H1_DNSSEC_RESULTS.md) — **PROVEN NOT VULNERABLE**
- [`stage3/H2_REGISTRAR_REENTRANCY_RESULTS.md`](./stage3/H2_REGISTRAR_REENTRANCY_RESULTS.md) — **PROVEN NOT VULNERABLE**
- [`stage3/H3_OFFCHAINDNS_RESULTS.md`](./stage3/H3_OFFCHAINDNS_RESULTS.md) — **PROVEN NOT VULNERABLE**
- [`stage3/STAGE3_ATTACK_SEQUENCES.md`](./stage3/STAGE3_ATTACK_SEQUENCES.md)
- [`stage3/STAGE3_TEST_MATRIX.md`](./stage3/STAGE3_TEST_MATRIX.md)
- [`stage3/STAGE3_FINAL_VERDICT.md`](./stage3/STAGE3_FINAL_VERDICT.md) — overall **CLEAN** for H1–H3

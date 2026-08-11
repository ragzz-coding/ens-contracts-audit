# Stage 4 — PoC Results

**Fixture:** `local/stage4/foundry/test/S4_StateMachine.t.sol`  
**Command:**

```bash
export PATH="$HOME/.foundry/bin:$PATH"
cd local/stage4/foundry
forge test --match-contract S4_NameWrapperStateMachineTest -vv
```

**Result:** `21 passed; 0 failed` (2026-08-11)

## Anti-false-positive summary

All attacks used unprivileged EOAs (`victim`, `attacker`, `parentOwner`, `childOwner`). Admin only deployed/wired controllers and minted via `base.addController(admin)` for fixture registration (setup privilege, not exploit privilege).

| Test | Initial | Attack | Final | Eligible impact? |
|---|---|---|---|---|
| wrap sync | victim NFT | — | synced wrapper ownership | n/a control |
| attacker wrap | victim NFT | `wrapETH2LD` as attacker | revert | no |
| CANNOT_TRANSFER | victim + fuse | transfer to attacker | revert; owner victim | no |
| PCC live | child @ childOwner | parent replace | revert | no |
| CCS | parent CCS | create child | revert | no |
| CANNOT_UNWRAP | victim | unwrap | revert | no |
| expired emancipated w/o CCS | child expired | parent recreate → attacker | **succeeds** | **no** — design (CCS not burned) |
| grace modify | wrapped in grace | unwrap | revert | no |
| wrapper expiry | expired PCC | attacker transfer | revert | no |
| grace register | grace | register | revert | no |
| multicall cross-node | victim owns A | mutate B | revert | no |
| node-check | victim | check A call B | revert | no |
| approval domains | victim | registry/wrapper op setAddr | revert until PR approve | no |

## Strongest “looks scary but isn’t”

1. **Parent recreates expired emancipated child** without `CANNOT_CREATE_SUBDOMAIN` — intentional; permanence requires burning CCS on parent.  
2. **Unwrapped NFT transfer without reclaim** — temporary registry lag; reclaim only by NFT owner.

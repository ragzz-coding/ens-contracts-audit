# Stage 3 — H2 ETHRegistrarController Register Reentrancy

**Target:** ENS `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
**Classification: PROVEN NOT VULNERABLE**

Mainnet controller: `0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547`  
Source: `contracts/ethregistrar/ETHRegistrarController.sol` `register` (approx. lines 247–345 @ tag)

---

## State machine (exact order, resolver path)

1. Price check (`msg.value >= base+premium`)  
2. Availability check  
3. Commitment age check  
4. **`delete commitments[commitment]`**  
5. `base.register(id, address(this), duration)` — NFT → controller  
6. `ens.setRecord(namehash, registration.owner, resolver, 0)` — ENS → owner  
7. **EXTERNAL:** `Resolver(resolver).multicallWithNodeCheck(namehash, data)`  
8. `base.transferFrom(this, registration.owner, id)` — NFT → owner  
9. Optional reverse for **`msg.sender`**  
10. Excess refund via `.transfer` to **`msg.sender`**

---

## Privilege separation

| Role | Powers in harness |
|---|---|
| Fork/setup admin | Deploy ENS, BaseRegistrar, controller; `addController`; fund accounts |
| Protocol owner | `withdraw()` recipient |
| Attacker EOA | `commit` / `register` with evil resolver; unprivileged |

---

## Phase A — benign callback observation

During evil `multicallWithNodeCheck`:

- `msg.sender` = controller  
- NFT owner = **controller** (not yet transferred)  
- ENS owner = **registration.owner** (already set)  
- Controller holds registration ETH  

Interim custody window exists — necessary but not sufficient for theft.

---

## Phase B — reentrant attempts

Harness: `local/stage3/foundry/test/H2_RegisterReentrancy.t.sol`, `src/harness/EvilResolver.sol`  
Output: `local/stage3/foundry/out_h2.txt`

| Attack | Outcome | Class |
|---|---|---|
| `transferFrom` NFT → attacker | Reverts (not owner/approved) | NO_IMPACT |
| `withdraw()` | Pays **admin/owner**, not attacker | NO_IMPACT |
| `withdraw` + overpay refund | Outer tx reverts | SAFE_REVERT |
| Reenter `register` same name | `NameNotAvailable` | NO_IMPACT |
| Reenter `register` 2nd committed name | May succeed; **does not steal victim name** | NO_IMPACT |
| `ens.setOwner` → attacker | Fails | NO_IMPACT |
| `renew` reenter | May succeed; no theft | NO_IMPACT |

---

## Phase C — value proof

Typical accounting (0.1 ETH fee):

- attacker Δ = −0.1 ETH  
- victim Δ = 0  
- controller Δ = +0.1 ETH (or 0 after withdraw-to-owner)  
- NFT/ENS final owner = **victim** (`registration.owner`)

No conservation failure favoring attacker. No unauthorized NFT/name ownership.

---

## Anti-false-positive gate

1. Unprivileged? YES  
2. Controls resolver? YES (in commitment)  
3. Victim cooperate? NO (for self-register; if registering for victim as owner, victim is beneficiary not cooperator)  
8. Eligible impact? **NO**  
9. Deterministic theft? **NO**

**PROVEN NOT VULNERABLE** — reentrancy is reachable but produces no Immunefi-eligible impact under tested paths.

Commands:

```bash
cd local/stage3/foundry
forge test --match-contract H2_ -vv
```

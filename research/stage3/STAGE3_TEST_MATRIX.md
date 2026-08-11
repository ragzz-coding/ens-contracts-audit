# Stage 3 — Test Matrix

| ID | Hypothesis | Test / artifact | Privilege | Expected invariant | Observed | Class |
|---|---|---|---|---|---|---|
| H1-B1 | H1 | `test_H1B_validRSASHA256_accepts` | anyone | valid proof accepts | PASS accept | control |
| H1-B2 | H1 | modified data/sig/key/trunc | anyone | invalid rejects | PASS reject | control |
| H1-C1 | H1 | Bleichenbacher e=3 forge vs v1.7.0 | anyone | forge rejects | PASS reject | kill residual |
| H1-C2 | H1 | same forge vs pre-patch harness | local harness | forge accepts (contrast) | PASS accept | proves vector |
| H1-C3 | H1 | empty/zero/hash-tail blobs | anyone | reject | PASS | mutation |
| H2-A | H2 | benign EvilResolver logging | attacker EOA | interim NFT@controller, ENS@owner | PASS | observe |
| H2-B1 | H2 | reenter transferFrom | attacker | cannot steal NFT | PASS NO_IMPACT | kill |
| H2-B2 | H2 | reenter withdraw | attacker | ETH→owner not attacker | PASS NO_IMPACT | kill |
| H2-B3 | H2 | withdraw+refund | attacker | SAFE_REVERT | PASS | kill |
| H2-B4 | H2 | reenter register same/other | attacker | no victim theft | PASS NO_IMPACT | kill |
| H2-B5 | H2 | reenter setOwner/renew | attacker | no theft | PASS NO_IMPACT | kill |
| H2-C | H2 | value accounting | attacker | conservation; owner=victim | PASS | kill |
| H3-B | H3 | victim context → victim addr | caller | correct resolve | PASS | control |
| H3-C1 | H3 | attacker context arg | caller | changes result but not victim path | PASS noted | kill reachability |
| H3-C2 | H3 | malformed / missing / duplicate keys | caller | revert/empty/first-wins | PASS | parser |
| H3-D | H3 | own-name narrative kill | — | not bounty | PASS | kill |

Commands to reproduce:

```bash
export PATH="$HOME/.foundry/bin:$PATH"
cd local/stage3/foundry
forge test --match-contract 'H1_|H2_' -vv
forge test --match-path test/H3_OffchainDNS.t.sol -vv
```

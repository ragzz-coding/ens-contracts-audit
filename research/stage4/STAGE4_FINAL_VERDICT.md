# Stage 4 — Final Verdict

**Overall: CLEAN**

No unprivileged, Immunefi-eligible authorization/state-machine failure was demonstrated against ENS v1.7.0 NameWrapper, registrar lifecycle, or resolver multicall authorization.

| Hypothesis | Result |
|---|---|
| S4-H1 ownership desync seize | PROVEN NOT VULNERABLE |
| S4-H2 fuse bypass | PROVEN NOT VULNERABLE |
| S4-H3 live PCC bypass | PROVEN NOT VULNERABLE |
| S4-H4 post-expiry parent recreate | PROVEN NOT VULNERABLE (design) |
| S4-H5 expiry boundary | PROVEN NOT VULNERABLE |
| S4-H6 NFT/registry divergence steal | PROVEN NOT VULNERABLE |
| S4-H7 multicall node confusion | PROVEN NOT VULNERABLE |
| S4-H8 cross-domain approvals | PROVEN NOT VULNERABLE |
| S4-H9 stale approvals | PROVEN NOT VULNERABLE |

H1–H3 from Stage 3 were **not** reopened.

## Strongest finding

Negative: fuse gates, grace freeze, multicall node binding, and separate approval domains held under adversarial local-fork transitions.

## Weakest assumption

Resolver tests used an auth/multicall/`setAddr` harness mirroring v1.7.0 `PublicResolver.isAuthorised` rather than the full profile contract graph. Auth predicates and Multicallable are the production code paths of interest; residual risk would be profile-specific setters ignoring `authorised` (not indicated by source review).

## Submodule proof

```
ens-contracts HEAD = 55b0eb7 (untouched)
v1.7.0             = 9b03493
git diff -- ens-contracts/ → empty
artifacts only under research/stage4 and local/stage4
```

# Scope classification

Pinned analysis commit for primary target: `9b034936a42f462fc04bc0a929a419ede5e18d59` (`v1.7.0`).

| Code | Purpose | Use in this research |
|---|---|---|
| Latest finalized release + mainnet deployment (`v1.7.0`) | Primary bounty target | All in-scope vulnerability work |
| Current `staging` | Historical / current-development reconnaissance | Lead generation only; never claim as mainnet bounty target without a newer finalized release + deployment |
| Older releases | Historical analysis only unless explicitly in scope | Diff blame, regression, understanding live leftovers |
| Testnet / pre-release | Only if the bounty carve-out is satisfied | Default: ignore |
| GitHub issues | Leads, not vulnerabilities | Track separately |
| Audits / known issues | Prior knowledge / regression hunting | Dedup before reporting |

## Hard rules derived from Immunefi ENS program

1. Mainnet eligibility requires the **latest finalized** `vx.x.x` that is **deployed to mainnet**.
2. A Git tag alone is not enough; deployment recognition comes from release artifacts / official deployment records (wiki / docs).
3. `staging` is out of scope by default for testnet/staging deployments; do not confuse the `staging` branch tip with the bounty target.
4. Primacy of Impact exists on Immunefi, but ENS out-of-scope exclusions control over it where stated.

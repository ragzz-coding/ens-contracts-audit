# Operating Rules

1. Treat this workspace as a private ENS security research copy. Never push to `ensdomains/*`.
2. Prefer evidence over assumption. Cite release tags, commits, deployment artifacts, official docs/wiki, and on-chain checks.
3. Keep classification strict: bounty target vs reconnaissance vs historical vs out-of-scope.
4. Do not treat GitHub issues as vulnerabilities. Treat audits as prior knowledge / regression hunting only.
5. All testing must use local forks. No mainnet or public-testnet exploitation.
6. Preserve reproducibility: record the exact upstream commit used for every analysis step.

Repository constraint: `ens-contracts/` is an official ENS Git submodule. Do not modify, commit, rewrite, checkout arbitrary branches in, or otherwise alter the upstream working tree unless explicitly instructed. The outer repository `ragzz-coding/ens-contracts-audit` is the research repository. All reports, scripts, models, tests, and generated research artifacts belong under the outer repository's `research/` or `local/` directories. Preserve the exact upstream commit used for every analysis step.

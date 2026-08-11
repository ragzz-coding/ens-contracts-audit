# ens-contracts-audit

Private ENS security research workspace.

## Layout

```
ens-contracts-audit/
├── ens-contracts/   # Official ENS source (submodule → ensdomains/ens-contracts)
├── research/        # Analysis and audit notes
└── local/           # Later local-fork work
```

## Setup

```bash
git clone --recurse-submodules https://github.com/ragzz-coding/ens-contracts-audit.git
# or after a normal clone:
git submodule update --init --recursive
```

## Important

- `ens-contracts/` origin is the official ENS repository (`ensdomains/ens-contracts`).
- Never push from inside `ens-contracts/` to ENS.
- This outer repo is the research copy only.

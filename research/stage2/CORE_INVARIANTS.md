# Stage 2 — Core Invariants

**Target:** `v1.7.0` @ `9b034936a42f462fc04bc0a929a419ede5e18d59`  
Invariants are written to be **falsifiable** on a local fork.

---

## Ownership & authorization

**I-01.** An unprivileged caller cannot cause `ens.owner(node)` to become an address of their choosing unless they satisfy one of: current `authorised(node)`, `authorised(parent)` via `setSubnodeOwner`, a BaseRegistrar/NameWrapper controller path that intentionally assigns that owner, or a DNSSEC `proveAndClaim` that verifies for a TXT owner equal to that address.

**I-02.** An unprivileged caller cannot cause `BaseRegistrar.ownerOf(labelhash)` to change unless they are the NFT owner/operator (active name) or a registrar controller performing register (available name).

**I-03.** An unprivileged caller cannot cause `NameWrapper.ownerOf(node)` (view) to become theirs unless they receive an ERC1155 transfer/mint authorized by the prior owner/operator/controller wrap path.

**I-04.** A child node cannot have its wrapped owner/fuses replaced by a parent caller while `PARENT_CANNOT_CONTROL` is set on the child and the child is not in the expired+recreate window defined by `_checkCanCallSetSubnodeOwner`.

**I-05.** Registry `operators[owner][op]` and PublicResolver approvals are distinct; holding one must not silently grant the other.

## Fuses & expiry

**I-06.** While `expiry >= block.timestamp`, a fuse bit that is set in raw storage cannot be cleared by `setFuses` / `setChildFuses` / remint paths (bits only OR); the only “clear” is expiry-time view clearing in `_clearOwnerAndFuses`.

**I-07.** Burning any non-parent-controlled owner fuse requires the resulting fuse word to include both `PARENT_CANNOT_CONTROL` and `CANNOT_UNWRAP`.

**I-08.** Child expiry after any legal call is `<=` parent wrapper expiry (after normalisation).

**I-09.** For `.eth` 2LDs with `IS_DOT_ETH`, while `expiry - GRACE_PERIOD < now`, `canModifyName` is false (no unwrap/setFuses/setRecord/etc. by owner).

**I-10.** `BaseRegistrar.available(id)` is true iff `expiries[id] + GRACE_PERIOD < now` (or never registered); during grace, `ownerOf` reverts and ERC721 transfers fail.

## Registration payment

**I-11.** Successful `ETHRegistrarController.register` nets `price.base + price.premium` ETH retained by the controller; excess returns only to `msg.sender`; no other address receives registration ETH inside `register`.

**I-12.** `register` cannot succeed without a commitment hash equal to `keccak256(abi.encode(registration))` with age ∈ `(minCommitmentAge, maxCommitmentAge]`; that commitment is deleted and not reusable.

**I-13.** The ERC721 owner and ENS owner resulting from `register` match `registration.owner` (resolver path: after final `transferFrom`; no-resolver path: direct mint to owner).

**I-14.** `renew` charges only `price.base` and cannot reduce expiry; it cannot make a name available early.

**I-15.** Registration payment cannot be redirected to an attacker-controlled address by choosing `referrer`, `resolver`, or `data`.

## Resolver & multicall

**I-16.** For `PublicResolver`, an unprivileged caller not trusted as ETH controller/reverse registrar cannot mutate records for `node` unless they are ENS/wrapper owner, PR operator for that owner, or PR delegate for that node.

**I-17.** `multicallWithNodeCheck(node, data)` reverts if any element’s bytes `[4:36] != node`.

**I-18.** `multicall` / `multicallWithNodeCheck` preserve `msg.sender` across `delegatecall` subcalls (no auth escalation via delegatecall alone).

**I-19.** An attacker cannot cause another user’s PublicResolver records to change solely by supplying a malicious `resolver` in *their own* unrelated registration, unless that malicious code is later invoked with trusted-controller privileges on PublicResolver (should not happen).

## Wrapper consistency

**I-20.** If `NameWrapper` reports a name as wrapped (`_isWrapped`), `ens.owner(node) == address(NameWrapper)` (except transient upgrade/unwrap windows within a single tx).

**I-21.** For wrapped `.eth` 2LDs, NameWrapper holds the BaseRegistrar NFT while wrapped; unwrap returns NFT to `registrant` and registry to `controller` as specified, and burns the ERC1155.

**I-22.** Reminting a still-unexpired name re-applies previously burned parent-controlled fuses and does not decrease expiry.

## Callbacks & composition

**I-23.** During `ETHRegistrarController.register`’s external resolver call, an attacker must not be able to: (a) assign the new NFT to themselves if `registration.owner` is not them; (b) steal retained registration ETH to themselves; (c) consume a different user’s commitment.

**I-24.** ERC1155/721 receiver callbacks during wrap/unwrap must not finalize foreign names’ ownership transfers without passing that name’s authorization checks.

## Offchain / DNSSEC / signatures

**I-25.** `DNSSECImpl.verifyRRSet` returns success only for proofs that validate under configured algorithms/digests against the DNSKEY/DS chain anchored as implemented (no Bleichenbacher-style forgery; PKCS#1 structure enforced).

**I-26.** `proveAndClaim` sets ENS owner exclusively to the address parsed from a verified `_ens` TXT `a=0x…` for that name — not `msg.sender` unless that address equals `msg.sender`.

**I-27.** Offchain resolution callbacks must not cause an onchain trusted contract to treat attacker gateway data as authorization to mutate ENS ownership/approvals (resolution may be wrong only under client-accepted trust model; ownership state must stay unchanged).

**I-28.** `DefaultReverseRegistrar.setNameForAddrWithSignature` sets reverse for `addr` only if `SignatureUtils` accepts a signature for the bound message `(this, selector, addr, expiry, name)` within the expiry window.

**I-29.** CCIP-read batching must not allow a gateway to make UniversalResolver accept a callback result for target `T` that was produced without `T`’s callback logic authorizing it (sender spoofing must not forge honest resolver crypto).

## Additional invariants from v1.7.0 code

**I-30.** `NameWrapper.approve` grantee cannot `safeTransferFrom` the token (only owner/operator can); approve is limited to extension authority paths.

**I-31.** Controllers on BaseRegistrar can mint/renew without paying through ETHRegistrarController; therefore an unprivileged account must not be able to become a registrar controller.

**I-32.** `withdraw` on ETHRegistrarController always sends to `owner()`, never to `msg.sender`.

**I-33.** Reverse bits in `register` cannot overwrite a third party’s reverse records (only `msg.sender`).

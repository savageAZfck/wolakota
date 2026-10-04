# wolakota — threat model

## Assets

- Consent history: what each party agreed to, when, and under which scope.
- Liveness of consent: whether a grant is currently active.
- Exit rights: either party's ability to leave unilaterally.

## Adversaries

- A counterparty that rewrites consent history after the fact.
- A counterparty that claims grants never ratified.
- A third party injecting revocations or ratifications.
- A party trying to hold the other in a contract they cannot leave.

## Guarantees

- **Two-party binding**: ratification requires both signatures on the
  identical canonical body. Neither side can ratify alone, and the
  counterparty key in the proposal cannot be substituted — `ratify()`
  checks the signing key matches the addressed counterparty.
- **Immutable history**: the TreatyBook hash-chains every event. Tampering
  with any entry breaks `verify_chain()` for everything after it.
- **Scope enforcement**: invocations are recorded only when the treaty is
  active and the scope is in the grant list. `ScopeDenied` otherwise.
- **Unilateral exit**: `Revocation` verifies the signer is a treaty party —
  either party can exit; outsiders cannot revoke.
- **Expiry is automatic**: TTL-elapsed treaties are `Expired` without
  needing either party to act — stale consent cannot linger silently.

## Non-goals

- Transport security — wolakota produces signed artifacts; carry them on
  your own encrypted channel (e.g. a P2P mesh).
- Enforcement on the counterparty's machine — the treaty proves consent was
  granted/withdrawn; it cannot stop a malicious peer's local code. It can
  prove they acted outside scope.
- Multi-party treaties — current version is bilateral. A council treaty
  (n-of-m ratification) is a future scope.

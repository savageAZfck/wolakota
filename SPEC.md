# wolakota — spec

## Identity

A treaty party is an **owner key** (ed25519), not a machine. Machines come
and go; the sovereignty is the party.

## Treaty identity

`treaty.id = sha256(canonical({initiator, counterparty, scopes, terms, created_at, ttl_secs}))`

The id does not cover signatures — it is stable from proposal through
ratification.

## Signed body

Both parties sign the identical canonical JSON body:

```
{id, initiator, counterparty, scopes, terms, created_at, ttl_secs}
```

Countersigning binds the counterparty to the treaty id, so scope lists
cannot drift between proposal and ratification.

## States

`Proposed → Active → (Expired | Revoked)` — plus `Void` when signatures
exist but fail verification. `Void` means never-active, never trusted.

- `Proposed`: initiator signature only.
- `Active`: both signatures verify, within TTL.
- `Expired`: TTL elapsed since `ratified_at` (`ttl_secs == 0` never expires).
- `Revoked`: a `Revocation` signed by either party was applied to the book.

## Revocation

`treaty_id`, `revoked_by`, `reason`, `ts`, `signature`. The book rejects
revocations not signed by a treaty party. Revocation is unilateral — both
sides hold exit rights at all times.

## TreatyBook

Append-only hash-chained event log:

```
event.hash = sha256(prev_hash || seq || kind || treaty_id || body_hash || ts)
```

`prev_hash` of the first event is the string `genesis`. Kinds: `propose`,
`ratify`, `invoke`, `revoke`. `verify_chain()` recomputes the full chain —
any inserted, dropped, reordered, or edited event breaks it.

## Invocation

`record_invocation` requires the treaty to be `Active` *and* the scope to
appear in the treaty scope list. Records the use of consent, not just the
grant — the history shows what was done, by whom, under which contract.

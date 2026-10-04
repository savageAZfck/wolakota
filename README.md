# wolakota

Inter-organism treaties — consent contracts between sovereign agents under different owner keys.

Named for the Lakota *wolakota*: peace and alliance between nations.

```toml
[dependencies]
wolakota = "0.1"
```

## What it is

Federation between independently-owned organisms needs a trust object both
sides can verify and neither can fake. A `wolakota` treaty is a
two-signature contract:

1. **Propose** — the initiator signs scopes, terms, and expiry.
2. **Ratify** — the counterparty countersigns the identical canonical body.
   Only then is the treaty active.
3. **Revoke** — either party exits with a signed revocation. Unilateral by
   design: consent you cannot withdraw was never consent.

Every lifecycle event lands in a hash-chained `TreatyBook`. Both parties can
hold the same book and verify it offline — consent history is not mutable,
and invocations record what was *done* under consent, not just what was
*granted*.

## Quickstart

```rust
use wolakota::{Identity, Treaty, TreatyBook, Scope};

let alice = Identity::generate();
let bob = Identity::generate();
let mut book = TreatyBook::new();

let mut treaty = Treaty::propose(
    &alice, &bob.public_key(),
    vec![Scope::ShareDreams, Scope::Inference { model: "qwen3-4b".into() }],
    "nightly dream exchange + delegated 4b inference",
    86_400 * 90,
);
book.record_proposal(treaty.clone())?;
treaty.ratify(&bob)?;
book.apply_ratification(treaty.clone())?;

// Is this scope live right now?
book.record_invocation(&treaty.id, &Scope::ShareDreams, now())?;
assert!(book.verify_chain());
```

## Scopes

Structured, both-sides-visible grants:

| Scope | Meaning |
|---|---|
| `ShareDreams` | peer dream digests may merge into local curation |
| `Inference { model }` | run inference on a named counterparty model |
| `Read { resource }` | read a named document/class of data |
| `Custody { ceremony }` | hold a memory-escrow share for the counterparty |
| `Custom { name }` | explicit free-form scope — last resort |

## Verify

```bash
cargo test          # 7 tests: lifecycle, wrong-party ratification, unilateral
                    # revocation, outsider denial, scope enforcement, expiry,
                    # chain tamper detection
cargo run --example treaty
```

## License

MIT

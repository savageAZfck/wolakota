use wolakota::{Identity, Revocation, Scope, Treaty, TreatyBook, TreatyState};

fn main() {
    // Two organisms, two owner keys — a federation of peers, not a
    // master and a minion.
    let alice = Identity::generate();
    let bob = Identity::generate();

    let mut book = TreatyBook::new();

    // Alice proposes: share dream digests, run inference on her 4b.
    let mut treaty = Treaty::propose(
        &alice,
        &bob.public_key(),
        vec![
            Scope::ShareDreams,
            Scope::Inference {
                model: "qwen3-4b".into(),
            },
        ],
        "nightly dream exchange + delegated 4b inference",
        86_400 * 90,
    );
    book.record_proposal(treaty.clone()).unwrap();
    println!("proposed {}  scopes: {:?}", &treaty.id[..12], treaty.scopes);

    // Bob ratifies — identical body, second signature.
    treaty.ratify(&bob).unwrap();
    book.apply_ratification(treaty.clone()).unwrap();
    println!("ratified — state: {:?}", book.state(&treaty.id, 0));

    // Invocations record the use of consent, not just the grant.
    book.record_invocation(&treaty.id, &Scope::ShareDreams, 0)
        .unwrap();

    // Either party can leave. Consent you can't withdraw is a cage.
    let rev = Revocation::issue(&bob, &treaty, "offboarding for the season");
    book.apply_revocation(rev).unwrap();
    println!("post-revocation state: {:?}", book.state(&treaty.id, 0));
    println!(
        "chain verifies: {} ({} events)",
        book.verify_chain(),
        book.events.len()
    );
}

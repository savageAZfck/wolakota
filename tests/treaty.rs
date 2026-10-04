use wolakota::{Identity, Revocation, Scope, Treaty, TreatyBook, TreatyState};

fn parties() -> (Identity, Identity) {
    (Identity::generate(), Identity::generate())
}

#[test]
fn propose_ratify_active() {
    let (alice, bob) = parties();
    let mut book = TreatyBook::new();
    let mut treaty = Treaty::propose(
        &alice,
        &bob.public_key(),
        vec![Scope::ShareDreams],
        "peer cognition exchange",
        0,
    );
    assert_eq!(treaty.state(now()), TreatyState::Proposed);
    book.record_proposal(treaty.clone()).unwrap();

    treaty.ratify(&bob).unwrap();
    book.apply_ratification(treaty.clone()).unwrap();
    assert_eq!(book.state(&treaty.id, now()), TreatyState::Active);
    assert!(book.verify_chain());
}

#[test]
fn ratify_by_wrong_party_fails() {
    let (alice, bob) = parties();
    let eve = Identity::generate();
    let mut treaty = Treaty::propose(&alice, &bob.public_key(), vec![Scope::ShareDreams], "t", 0);
    assert!(treaty.ratify(&eve).is_err());
}

#[test]
fn either_party_revokes() {
    let (alice, bob) = parties();
    let mut book = TreatyBook::new();
    let mut treaty =
        Treaty::propose(&alice, &bob.public_key(), vec![Scope::ShareDreams], "t", 0);
    book.record_proposal(treaty.clone()).unwrap();
    treaty.ratify(&bob).unwrap();
    book.apply_ratification(treaty.clone()).unwrap();

    // Counterparty can exit unilaterally.
    let rev = Revocation::issue(&bob, &treaty, "done for now");
    book.apply_revocation(rev).unwrap();
    assert_eq!(book.state(&treaty.id, now()), TreatyState::Revoked);
    assert!(book.verify_chain());
}

#[test]
fn outsider_revocation_denied() {
    let (alice, bob) = parties();
    let eve = Identity::generate();
    let mut book = TreatyBook::new();
    let mut treaty =
        Treaty::propose(&alice, &bob.public_key(), vec![Scope::ShareDreams], "t", 0);
    book.record_proposal(treaty.clone()).unwrap();
    treaty.ratify(&bob).unwrap();
    book.apply_ratification(treaty.clone()).unwrap();

    let rev = Revocation::issue(&eve, &treaty, "not a party");
    assert!(book.apply_revocation(rev).is_err());
    assert_eq!(book.state(&treaty.id, now()), TreatyState::Active);
}

#[test]
fn invocation_requires_active_and_granted_scope() {
    let (alice, bob) = parties();
    let mut book = TreatyBook::new();
    let mut treaty = Treaty::propose(
        &alice,
        &bob.public_key(),
        vec![Scope::ShareDreams],
        "dream sharing only",
        0,
    );
    book.record_proposal(treaty.clone()).unwrap();
    treaty.ratify(&bob).unwrap();
    book.apply_ratification(treaty.clone()).unwrap();

    // Granted scope records.
    book.record_invocation(&treaty.id, &Scope::ShareDreams, now()).unwrap();
    // Ungranted scope denies.
    assert!(book
        .record_invocation(&treaty.id, &Scope::Read { resource: "ledger".into() }, now())
        .is_err());
    assert!(book.verify_chain());
}

#[test]
fn expired_treaty_is_inactive() {
    let (alice, bob) = parties();
    let mut treaty =
        Treaty::propose(&alice, &bob.public_key(), vec![Scope::ShareDreams], "t", 60);
    treaty.ratify(&bob).unwrap();
    let ratified = treaty.ratified_at.unwrap();
    assert_eq!(treaty.state(ratified + 30), TreatyState::Active);
    assert_eq!(treaty.state(ratified + 120), TreatyState::Expired);
}

#[test]
fn chain_detects_tampering() {
    let (alice, bob) = parties();
    let mut book = TreatyBook::new();
    let mut treaty =
        Treaty::propose(&alice, &bob.public_key(), vec![Scope::ShareDreams], "t", 0);
    book.record_proposal(treaty.clone()).unwrap();
    treaty.ratify(&bob).unwrap();
    book.apply_ratification(treaty).unwrap();

    assert!(book.verify_chain());
    book.events[0].kind = "revoke".to_string();
    assert!(!book.verify_chain());
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

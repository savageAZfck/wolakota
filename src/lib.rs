//! wolakota — inter-organism treaties.
//!
//! Named for the Lakota *wolakota* — peace and alliance between nations.
//! Sovereign organisms under *different* owner keys cannot simply trust
//! each other: each side needs a signed, scoped, revocable record of what
//! it consented to and what the other party consented to. That record is
//! a treaty.
//!
//! A treaty is a two-signature contract:
//!
//! 1. The initiator proposes — scopes, terms, expiry — signed by their key.
//! 2. The counterparty ratifies — signs the identical canonical body.
//!    Only then is the treaty active.
//! 3. Either party may revoke at any time with a signed revocation —
//!    sovereignty means exit is always available; a treaty you cannot
//!    leave is a cage, not a contract.
//!
//! All activity lands in a hash-chained [`TreatyBook`]: propose, ratify,
//! invoke (a scoped use of the treaty), revoke. Both parties can verify
//! the chain offline — neither side can rewrite the history of consent.
//!
//! ```no_run
//! use wolakota::{Identity, Treaty, TreatyBook, Scope};
//!
//! let alice = Identity::generate();
//! let bob = Identity::generate();
//! let treaty = Treaty::propose(&alice, &bob.public_key(),
//!     vec![Scope::ShareDreams, Scope::Inference { model: "qwen-4b".into() }],
//!     "peer cognition exchange", 86_400 * 30);
//! // alice sends treaty to bob; bob ratifies by countersigning.
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Debug)]
pub enum Error {
    BadTreaty(String),
    BadSignature(String),
    NotActive(String),
    ScopeDenied(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadTreaty(m) => write!(f, "bad treaty: {m}"),
            Error::BadSignature(m) => write!(f, "bad signature: {m}"),
            Error::NotActive(m) => write!(f, "treaty not active: {m}"),
            Error::ScopeDenied(m) => write!(f, "scope denied: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

/// An ed25519 identity — the *owner* key of an organism, not a machine.
/// Machines come and go; the party to a treaty is the sovereignty.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    fn sign(&self, payload: &BTreeMap<String, Value>) -> String {
        hex::encode(self.signing.sign(canonical(payload).as_bytes()).to_bytes())
    }
}

fn canonical(payload: &BTreeMap<String, Value>) -> String {
    serde_json::to_string(payload).expect("BTreeMap<String, Value> always serializes")
}

fn verify(pub_hex: &str, payload: &BTreeMap<String, Value>, sig_hex: &str) -> bool {
    let (Ok(pk_bytes), Ok(sig_bytes)) = (hex::decode(pub_hex), hex::decode(sig_hex)) else {
        return false;
    };
    let (Ok(pk_arr), Ok(sig_arr)): (Result<[u8; 32], _>, Result<[u8; 64], _>) = (
        pk_bytes.try_into().map_err(|_| ()),
        sig_bytes.try_into().map_err(|_| ()),
    ) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(canonical(payload).as_bytes(), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Scopes — what the treaty grants
// ---------------------------------------------------------------------------

/// A scoped grant inside a treaty. Both parties read the same list —
/// there is no asymmetric consent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum Scope {
    /// Peer dream shares may merge into local nightly curation.
    ShareDreams,
    /// Inference may run against a named model on the counterparty.
    Inference { model: String },
    /// Read a named document/class of data.
    Read { resource: String },
    /// Memory escrow custody — hold a share for the counterparty.
    Custody { ceremony: String },
    /// An explicitly named free-form scope — last resort; structured
    /// scopes exist so both sides know what they signed.
    Custom { name: String },
}

impl Scope {
    fn canonical(&self) -> Value {
        serde_json::to_value(self).expect("scope serializes")
    }
}

// ---------------------------------------------------------------------------
// Treaty lifecycle
// ---------------------------------------------------------------------------

/// The treaty record. Signatures accumulate across the lifecycle:
/// `initiator_sig` at propose, `counterparty_sig` at ratify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Treaty {
    /// sha256 of the proposed body — stable id for both parties' books.
    pub id: String,
    pub initiator: String,
    pub counterparty: String,
    pub scopes: Vec<Scope>,
    /// Human-legible intent, hashed into the id and signed.
    pub terms: String,
    pub created_at: u64,
    /// Seconds from ratification until the treaty expires on its own.
    /// Zero means no expiry — choose deliberately.
    pub ttl_secs: u64,
    pub initiator_sig: String,
    /// Set when the counterparty ratifies.
    pub counterparty_sig: Option<String>,
    /// Set at ratification — expiry and active windows run from it.
    pub ratified_at: Option<u64>,
}

impl Treaty {
    /// Propose a treaty: signed by the initiator, inert until ratified.
    pub fn propose(
        initiator: &Identity,
        counterparty: &str,
        scopes: Vec<Scope>,
        terms: &str,
        ttl_secs: u64,
    ) -> Self {
        let mut t = Self {
            id: String::new(),
            initiator: initiator.public_key(),
            counterparty: counterparty.to_string(),
            scopes,
            terms: terms.to_string(),
            created_at: now_secs(),
            ttl_secs,
            initiator_sig: String::new(),
            counterparty_sig: None,
            ratified_at: None,
        };
        t.id = sha256_hex(canonical(&t.id_body()).as_bytes());
        t.initiator_sig = initiator.sign(&t.signed_body());
        t
    }

    /// Identity body — the id preimage. Id does not cover signatures.
    fn id_body(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("initiator".into(), json!(self.initiator));
        m.insert("counterparty".into(), json!(self.counterparty));
        m.insert(
            "scopes".into(),
            json!(self
                .scopes
                .iter()
                .map(|s| s.canonical())
                .collect::<Vec<_>>()),
        );
        m.insert("terms".into(), json!(self.terms));
        m.insert("created_at".into(), json!(self.created_at));
        m.insert("ttl_secs".into(), json!(self.ttl_secs));
        m
    }

    /// The ratification body — what both parties sign. Countersigning
    /// binds the counterparty to the treaty *id*, so scope lists cannot
    /// drift between proposal and ratification.
    fn signed_body(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("id".into(), json!(self.id));
        m.insert("initiator".into(), json!(self.initiator));
        m.insert("counterparty".into(), json!(self.counterparty));
        m.insert(
            "scopes".into(),
            json!(self
                .scopes
                .iter()
                .map(|s| s.canonical())
                .collect::<Vec<_>>()),
        );
        m.insert("terms".into(), json!(self.terms));
        m.insert("created_at".into(), json!(self.created_at));
        m.insert("ttl_secs".into(), json!(self.ttl_secs));
        m
    }

    /// Counterparty ratification. Verifies the initiator signature and
    /// the counterparty key, then countersigns the identical body.
    pub fn ratify(&mut self, counterparty: &Identity) -> Result<(), Error> {
        if self.counterparty_sig.is_some() {
            return Err(Error::BadTreaty("already ratified".into()));
        }
        if !verify(&self.initiator, &self.signed_body(), &self.initiator_sig) {
            return Err(Error::BadSignature("initiator signature invalid".into()));
        }
        if counterparty.public_key() != self.counterparty {
            return Err(Error::BadTreaty(
                "this treaty is addressed to a different counterparty".into(),
            ));
        }
        self.counterparty_sig = Some(counterparty.sign(&self.signed_body()));
        self.ratified_at = Some(now_secs());
        Ok(())
    }

    /// Lifecycle state at `at` (seconds since epoch).
    pub fn state(&self, at: u64) -> TreatyState {
        if self.counterparty_sig.is_none() {
            return TreatyState::Proposed;
        }
        let ratified = self.ratified_at.unwrap_or(self.created_at);
        if self.ttl_secs > 0 && at > ratified.saturating_add(self.ttl_secs) {
            return TreatyState::Expired;
        }
        if !verify(&self.initiator, &self.signed_body(), &self.initiator_sig) {
            return TreatyState::Void("initiator signature failed");
        }
        let cp_sig = self.counterparty_sig.as_deref().unwrap_or_default();
        if !verify(&self.counterparty, &self.signed_body(), cp_sig) {
            return TreatyState::Void("counterparty signature failed");
        }
        TreatyState::Active
    }

    /// Whether `scope` is granted while the treaty is active at `at`.
    pub fn permits(&self, scope: &Scope, at: u64) -> bool {
        self.state(at) == TreatyState::Active && self.scopes.contains(scope)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreatyState {
    Proposed,
    Active,
    Expired,
    Revoked,
    /// Signatures exist but fail — treat as never-active.
    Void(&'static str),
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// A signed exit from a treaty. Either party may revoke unilaterally —
/// consent that cannot be withdrawn was never consent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocation {
    pub treaty_id: String,
    pub revoked_by: String,
    pub reason: String,
    pub ts: u64,
    pub signature: String,
}

impl Revocation {
    /// Issue a revocation. `signer` must be a treaty party — enforcement
    /// happens in [`TreatyBook::apply_revocation`], which checks the signature and
    /// membership together.
    pub fn issue(signer: &Identity, treaty: &Treaty, reason: &str) -> Self {
        let mut r = Self {
            treaty_id: treaty.id.clone(),
            revoked_by: signer.public_key(),
            reason: reason.to_string(),
            ts: now_secs(),
            signature: String::new(),
        };
        r.signature = signer.sign(&r.payload());
        r
    }

    fn payload(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("treaty_id".into(), json!(self.treaty_id));
        m.insert("revoked_by".into(), json!(self.revoked_by));
        m.insert("reason".into(), json!(self.reason));
        m.insert("ts".into(), json!(self.ts));
        m
    }

    pub fn verify(&self) -> bool {
        verify(&self.revoked_by, &self.payload(), &self.signature)
    }
}

// ---------------------------------------------------------------------------
// TreatyBook — the hash-chained record
// ---------------------------------------------------------------------------

/// One entry in the treaty book: a lifecycle event, hash-chained.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreatyEvent {
    pub seq: u64,
    pub kind: String,
    pub treaty_id: String,
    /// sha256 of the event payload body.
    pub body_hash: String,
    pub ts: u64,
    /// sha256 of (prev_hash + canonical event without this field).
    pub hash: String,
}

/// Append-only, hash-chained treaty record. Both parties can keep the
/// same book and verify it offline — consent history is not mutable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TreatyBook {
    pub treaties: Vec<Treaty>,
    pub revocations: Vec<Revocation>,
    pub events: Vec<TreatyEvent>,
}

impl TreatyBook {
    pub fn new() -> Self {
        Self::default()
    }

    fn chain_tip(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "genesis".into())
    }

    fn append(&mut self, kind: &str, treaty_id: &str, body: &BTreeMap<String, Value>) {
        let body_hash = sha256_hex(canonical(body).as_bytes());
        let prev = self.chain_tip();
        let mut ev = TreatyEvent {
            seq: self.events.len() as u64,
            kind: kind.to_string(),
            treaty_id: treaty_id.to_string(),
            body_hash,
            ts: now_secs(),
            hash: String::new(),
        };
        let preimage = format!(
            "{prev}:{}:{}:{}:{}:{}",
            ev.seq, ev.kind, ev.treaty_id, ev.body_hash, ev.ts
        );
        ev.hash = sha256_hex(preimage.as_bytes());
        self.events.push(ev);
    }

    /// Record a proposal. The treaty enters as Proposed.
    pub fn record_proposal(&mut self, treaty: Treaty) -> Result<(), Error> {
        if !verify(
            &treaty.initiator,
            &treaty.signed_body(),
            &treaty.initiator_sig,
        ) {
            return Err(Error::BadSignature(
                "proposal not signed by initiator".into(),
            ));
        }
        if self.treaties.iter().any(|t| t.id == treaty.id) {
            return Err(Error::BadTreaty("duplicate treaty id".into()));
        }
        self.append("propose", &treaty.id, &treaty.signed_body());
        self.treaties.push(treaty);
        Ok(())
    }

    /// Apply a ratification: the counterparty's countersigned treaty.
    /// The stored proposal must match byte-for-byte on signed fields.
    pub fn apply_ratification(&mut self, ratified: Treaty) -> Result<(), Error> {
        let Some(existing) = self.treaties.iter_mut().find(|t| t.id == ratified.id) else {
            return Err(Error::BadTreaty("no proposal for this treaty id".into()));
        };
        if existing.signed_body() != ratified.signed_body() {
            return Err(Error::BadTreaty(
                "ratified body does not match the proposal".into(),
            ));
        }
        *existing = ratified.clone();
        self.append("ratify", &ratified.id, &ratified.signed_body());
        Ok(())
    }

    /// Apply a revocation — the revoker must be a treaty party with a
    /// valid signature. Either party can exit; nobody can hold the other.
    pub fn apply_revocation(&mut self, rev: Revocation) -> Result<(), Error> {
        if !rev.verify() {
            return Err(Error::BadSignature("revocation signature invalid".into()));
        }
        let Some(treaty) = self.treaties.iter().find(|t| t.id == rev.treaty_id) else {
            return Err(Error::BadTreaty("no treaty for this revocation".into()));
        };
        if rev.revoked_by != treaty.initiator && rev.revoked_by != treaty.counterparty {
            return Err(Error::BadSignature(
                "revocation not signed by a treaty party".into(),
            ));
        }
        self.append("revoke", &rev.treaty_id, &rev.payload());
        self.revocations.push(rev);
        Ok(())
    }

    /// Effective state: treaty lifecycle folded with revocations.
    pub fn state(&self, treaty_id: &str, at: u64) -> TreatyState {
        if self.revocations.iter().any(|r| r.treaty_id == treaty_id) {
            return TreatyState::Revoked;
        }
        self.treaties
            .iter()
            .find(|t| t.id == treaty_id)
            .map(|t| t.state(at))
            .unwrap_or(TreatyState::Void("unknown treaty"))
    }

    /// Record an invocation — a scoped use of an active treaty. Both
    /// parties' books should record the same invocation stream, so
    /// consent history shows not just what was agreed but what was done.
    pub fn record_invocation(
        &mut self,
        treaty_id: &str,
        scope: &Scope,
        at: u64,
    ) -> Result<(), Error> {
        let Some(treaty) = self.treaties.iter().find(|t| t.id == treaty_id) else {
            return Err(Error::BadTreaty("no treaty".into()));
        };
        if self.state(treaty_id, at) != TreatyState::Active {
            return Err(Error::NotActive(format!("{:?}", self.state(treaty_id, at))));
        }
        if !treaty.scopes.contains(scope) {
            return Err(Error::ScopeDenied(format!(
                "scope {scope:?} not granted by treaty {treaty_id}"
            )));
        }
        let mut m = BTreeMap::new();
        m.insert("scope".into(), scope.canonical());
        self.append("invoke", treaty_id, &m);
        Ok(())
    }

    /// Verify the hash chain end to end. Any inserted, dropped, or
    /// reordered event breaks it.
    pub fn verify_chain(&self) -> bool {
        let mut prev = "genesis".to_string();
        for (i, ev) in self.events.iter().enumerate() {
            if ev.seq != i as u64 {
                return false;
            }
            let preimage = format!(
                "{prev}:{}:{}:{}:{}:{}",
                ev.seq, ev.kind, ev.treaty_id, ev.body_hash, ev.ts
            );
            if ev.hash != sha256_hex(preimage.as_bytes()) {
                return false;
            }
            prev = ev.hash.clone();
        }
        true
    }
}

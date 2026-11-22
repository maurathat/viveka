//! Records, addresses and signatures: SPEC.md sections 3 to 5.

use crate::json::{self, InputError};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{Map, Value, json};
use std::fmt;

/// A record's `blake3:<64 lowercase hex>` label (section 1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(String);

impl Address {
    /// Parse a label, refusing anything but `blake3:` and 64 lowercase hex.
    pub fn parse(s: &str) -> Option<Address> {
        let hex = s.strip_prefix("blake3:")?;
        (hex.len() == 64 && is_lower_hex(hex)).then(|| Address(s.to_string()))
    }
    /// The address of a JSON value: `uor-addr`'s JSON realization.
    pub fn of(v: &Value) -> Result<Address, RecordError> {
        let bytes = serde_json::to_vec(v).map_err(|e| RecordError::Address(e.to_string()))?;
        let out =
            uor_addr::json::address(&bytes).map_err(|e| RecordError::Address(format!("{e:?}")))?;
        Address::parse(out.address.as_ref())
            .ok_or_else(|| RecordError::Address("uor-addr returned no blake3 label".into()))
    }
    /// The label as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// The 64 hex characters, the record's file name in a folder store.
    pub fn hex(&self) -> &str {
        &self.0["blake3:".len()..]
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An Ed25519 public key, written `ed25519:<64 lowercase hex>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(String);

impl Key {
    /// Parse a key, refusing anything that is not a valid Ed25519 point.
    pub fn parse(s: &str) -> Option<Key> {
        let hex = s.strip_prefix("ed25519:")?;
        let bytes: [u8; 32] = unhex(hex)?.try_into().ok()?;
        VerifyingKey::from_bytes(&bytes).ok()?;
        Some(Key(s.to_string()))
    }
    fn verifying(&self) -> VerifyingKey {
        let bytes: [u8; 32] = unhex(&self.0["ed25519:".len()..])
            .and_then(|b| b.try_into().ok())
            .expect("checked in parse");
        VerifyingKey::from_bytes(&bytes).expect("checked in parse")
    }
    /// The key as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A private key that signs records.
pub struct Signer(SigningKey);

impl Signer {
    /// A new key from the operating system's randomness.
    pub fn generate() -> Result<Signer, RecordError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| RecordError::Random(e.to_string()))?;
        Ok(Signer(SigningKey::from_bytes(&seed)))
    }
    /// The key whose 32-byte seed is `hex` (64 hex characters).
    pub fn from_hex(hex: &str) -> Option<Signer> {
        let seed: [u8; 32] = unhex(hex.trim())?.try_into().ok()?;
        Some(Signer(SigningKey::from_bytes(&seed)))
    }
    /// The seed as 64 hex characters. Keep it secret.
    pub fn to_hex(&self) -> String {
        hex(&self.0.to_bytes())
    }
    /// The matching public key.
    pub fn key(&self) -> Key {
        Key(format!(
            "ed25519:{}",
            hex(self.0.verifying_key().as_bytes())
        ))
    }
    /// Sign `record`: the signature covers the 71 bytes of its address.
    pub fn sign(&self, record: Record) -> Result<Signed, RecordError> {
        if record.author != self.key() {
            return Err(RecordError::Envelope(
                "author is not the signing key".into(),
            ));
        }
        let address = record.address()?;
        let sig = hex(&self.0.sign(address.as_str().as_bytes()).to_bytes());
        Ok(Signed {
            record,
            sig,
            address,
        })
    }
}

/// The kinds of record (section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Genesis,
    Problem,
    Proposal,
    Decision,
    Attempt,
    Outcome,
}

impl Kind {
    pub const ALL: [Kind; 6] = [
        Kind::Genesis,
        Kind::Problem,
        Kind::Proposal,
        Kind::Decision,
        Kind::Attempt,
        Kind::Outcome,
    ];
    /// The kind's name in a record.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Genesis => "genesis",
            Kind::Problem => "problem",
            Kind::Proposal => "proposal",
            Kind::Decision => "decision",
            Kind::Attempt => "attempt",
            Kind::Outcome => "outcome",
        }
    }
    /// The kind named `s`.
    pub fn from_name(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == s)
    }
}

/// Why a record was refused before it was ever checked against a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The bytes break the input rules of section 2.
    Input(InputError),
    /// The envelope of section 3 is wrong.
    Envelope(String),
    /// The body does not fit its kind (section 4).
    Body(String),
    /// The address could not be computed.
    Address(String),
    /// The signature is malformed or does not verify.
    Signature,
    /// The operating system gave no randomness.
    Random(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Input(e) => write!(f, "{e}"),
            RecordError::Envelope(m) => write!(f, "envelope: {m}"),
            RecordError::Body(m) => write!(f, "body: {m}"),
            RecordError::Address(m) => write!(f, "address: {m}"),
            RecordError::Signature => f.write_str("signature does not verify"),
            RecordError::Random(m) => write!(f, "no randomness: {m}"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<InputError> for RecordError {
    fn from(e: InputError) -> Self {
        RecordError::Input(e)
    }
}

/// One record: the envelope of section 3 around a kind's body.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub kind: Kind,
    pub chain: String,
    pub seq: u64,
    pub parent: Option<Address>,
    pub author: Key,
    pub time: i64,
    pub nonce: String,
    pub body: Map<String, Value>,
}

impl Record {
    /// A record with a fresh nonce.
    pub fn new(
        kind: Kind,
        chain: &str,
        seq: u64,
        parent: Option<Address>,
        author: Key,
        time: i64,
        body: Map<String, Value>,
    ) -> Result<Record, RecordError> {
        let mut n = [0u8; 16];
        getrandom::getrandom(&mut n).map_err(|e| RecordError::Random(e.to_string()))?;
        let r = Record {
            kind,
            chain: chain.to_string(),
            seq,
            parent,
            author,
            time,
            nonce: hex(&n),
            body,
        };
        r.check()?;
        Ok(r)
    }

    /// The record as the JSON object that is addressed.
    pub fn to_value(&self) -> Value {
        json!({
            "viveka": 1,
            "kind": self.kind.name(),
            "chain": self.chain,
            "seq": self.seq,
            "parent": self.parent.as_ref().map(|a| a.as_str()),
            "author": self.author.as_str(),
            "time": self.time,
            "nonce": self.nonce,
            "body": Value::Object(self.body.clone()),
        })
    }

    /// The record's address.
    pub fn address(&self) -> Result<Address, RecordError> {
        Address::of(&self.to_value())
    }

    /// Read a record from a parsed JSON value, checking the envelope and
    /// the shape of the body (rule V1).
    pub fn from_value(v: &Value) -> Result<Record, RecordError> {
        json::check(v)?;
        let o = v
            .as_object()
            .ok_or_else(|| env("a record is a JSON object"))?;
        exact(
            o,
            &[
                "viveka", "kind", "chain", "seq", "parent", "author", "time", "nonce", "body",
            ],
        )
        .map_err(RecordError::Envelope)?;
        if o["viveka"].as_i64() != Some(1) {
            return Err(env("`viveka` must be 1"));
        }
        let kind = o["kind"]
            .as_str()
            .and_then(Kind::from_name)
            .ok_or_else(|| env("unknown `kind`"))?;
        let chain = o["chain"]
            .as_str()
            .ok_or_else(|| env("`chain` must be text"))?
            .to_string();
        let seq = o["seq"]
            .as_u64()
            .ok_or_else(|| env("`seq` must be a whole number, 0 or more"))?;
        let parent = match &o["parent"] {
            Value::Null => None,
            Value::String(s) => {
                Some(Address::parse(s).ok_or_else(|| env("`parent` is not an address"))?)
            }
            _ => return Err(env("`parent` must be an address or null")),
        };
        let author = o["author"]
            .as_str()
            .and_then(Key::parse)
            .ok_or_else(|| env("`author` is not an Ed25519 key"))?;
        let time = o["time"]
            .as_i64()
            .ok_or_else(|| env("`time` must be a whole number"))?;
        let nonce = o["nonce"]
            .as_str()
            .ok_or_else(|| env("`nonce` must be text"))?
            .to_string();
        let body = o["body"]
            .as_object()
            .ok_or_else(|| env("`body` must be an object"))?
            .clone();
        let r = Record {
            kind,
            chain,
            seq,
            parent,
            author,
            time,
            nonce,
            body,
        };
        r.check()?;
        Ok(r)
    }

    /// Everything about a record that can be checked without its chain.
    pub fn check(&self) -> Result<(), RecordError> {
        json::check(&Value::Object(self.body.clone()))?;
        let name_ok = (1..=64).contains(&self.chain.len())
            && self
                .chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok {
            return Err(env("`chain` must be 1 to 64 characters of a-z, 0-9 and -"));
        }
        if !(self.nonce.len() == 32 && is_lower_hex(&self.nonce)) {
            return Err(env("`nonce` must be 32 lowercase hex characters"));
        }
        if self.seq > json::MAX_INT as u64 {
            return Err(env("`seq` is out of range"));
        }
        if (self.seq == 0) != (self.kind == Kind::Genesis)
            || (self.seq == 0) != self.parent.is_none()
        {
            return Err(env(
                "record 0, and only record 0, is a genesis with no parent",
            ));
        }
        body_shape(self.kind, &self.body).map_err(RecordError::Body)
    }

    /// The address a body member names.
    pub fn address_in(&self, member: &str) -> Option<Address> {
        self.body.get(member)?.as_str().and_then(Address::parse)
    }
    /// The keys a genesis body lists under `member`.
    pub fn keys_in(&self, member: &str) -> Vec<Key> {
        strings(&self.body, member)
            .iter()
            .filter_map(|s| Key::parse(s))
            .collect()
    }
    /// The strings a body lists under `member`.
    pub fn strings_in(&self, member: &str) -> Vec<String> {
        strings(&self.body, member)
    }
}

/// A record with its author's signature and its address (section 3).
#[derive(Debug, Clone, PartialEq)]
pub struct Signed {
    pub record: Record,
    pub sig: String,
    pub address: Address,
}

impl Signed {
    /// The stored form: `{"record": ..., "sig": ...}`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let v = json!({ "record": self.record.to_value(), "sig": self.sig });
        let mut out = serde_json::to_vec_pretty(&v).expect("a JSON value serializes");
        out.push(b'\n');
        out
    }

    /// Read a stored record, recomputing its address and checking its
    /// signature (rules V1 and V3; V2 is the caller's comparison of
    /// `address` with the address the bytes were stored under).
    pub fn from_bytes(bytes: &[u8]) -> Result<Signed, RecordError> {
        let v = json::parse(bytes)?;
        let o = v
            .as_object()
            .ok_or_else(|| env("a signed record is a JSON object"))?;
        exact(o, &["record", "sig"]).map_err(RecordError::Envelope)?;
        let record = Record::from_value(&o["record"])?;
        let sig = o["sig"].as_str().ok_or(RecordError::Signature)?.to_string();
        // Address the value as it was stored, not as re-serialized: the
        // same record always has the same address either way, and this
        // keeps a tampered member from being normalized away.
        let address = Address::of(&o["record"])?;
        let raw: [u8; 64] = unhex(&sig)
            .and_then(|b| b.try_into().ok())
            .ok_or(RecordError::Signature)?;
        record
            .author
            .verifying()
            .verify(address.as_str().as_bytes(), &Signature::from_bytes(&raw))
            .map_err(|_| RecordError::Signature)?;
        Ok(Signed {
            record,
            sig,
            address,
        })
    }
}

fn env(m: &str) -> RecordError {
    RecordError::Envelope(m.to_string())
}

/// `o` has exactly the members `names`.
fn exact(o: &Map<String, Value>, names: &[&str]) -> Result<(), String> {
    for n in names {
        if !o.contains_key(*n) {
            return Err(format!("missing member `{n}`"));
        }
    }
    match o.keys().find(|k| !names.contains(&k.as_str())) {
        Some(k) => Err(format!("unknown member `{k}`")),
        None => Ok(()),
    }
}

fn strings(o: &Map<String, Value>, member: &str) -> Vec<String> {
    o.get(member)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn text(o: &Map<String, Value>, m: &str) -> Result<(), String> {
    match o[m].as_str() {
        Some(s) if !s.is_empty() => Ok(()),
        _ => Err(format!("`{m}` must be non-empty text")),
    }
}

fn address(o: &Map<String, Value>, m: &str) -> Result<(), String> {
    o[m].as_str()
        .and_then(Address::parse)
        .map(|_| ())
        .ok_or_else(|| format!("`{m}` must be an address"))
}

fn list<T>(
    o: &Map<String, Value>,
    m: &str,
    what: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, String> {
    let a = o[m]
        .as_array()
        .ok_or_else(|| format!("`{m}` must be an array of {what}"))?;
    let out: Option<Vec<T>> = a.iter().map(|v| v.as_str().and_then(&parse)).collect();
    let out = out.ok_or_else(|| format!("`{m}` must be an array of {what}"))?;
    let mut seen = std::collections::BTreeSet::new();
    if !a.iter().all(|v| seen.insert(v.as_str())) {
        return Err(format!("`{m}` lists an entry twice"));
    }
    Ok(out)
}

/// An object whose every value is a whole number.
fn numbers(o: &Map<String, Value>, m: &str) -> Result<(), String> {
    let inner = o[m]
        .as_object()
        .ok_or_else(|| format!("`{m}` must be an object of whole numbers"))?;
    if inner.values().all(|v| v.as_i64().is_some()) {
        Ok(())
    } else {
        Err(format!("`{m}` must hold only whole numbers"))
    }
}

fn name(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// The shape of a kind's body (section 4), without reference to a chain.
fn body_shape(kind: Kind, o: &Map<String, Value>) -> Result<(), String> {
    match kind {
        Kind::Genesis => {
            exact(o, &["writers", "approvers", "quorum", "scope", "purpose"])?;
            let writers = list(o, "writers", "keys", Key::parse)?;
            let approvers = list(o, "approvers", "keys", Key::parse)?;
            list(o, "scope", "parameter names", name)?;
            text(o, "purpose")?;
            let q = o["quorum"]
                .as_u64()
                .ok_or("`quorum` must be a whole number")?;
            if writers.is_empty() {
                return Err("`writers` must name at least one key".into());
            }
            if q < 1 || q > approvers.len() as u64 {
                return Err(
                    "`quorum` must be at least 1 and at most the number of approvers".into(),
                );
            }
            Ok(())
        }
        Kind::Problem => {
            exact(o, &["title", "measures"])?;
            text(o, "title")?;
            if list(o, "measures", "measure names", name)?.is_empty() {
                return Err("`measures` must name at least one measure".into());
            }
            Ok(())
        }
        Kind::Proposal => {
            exact(o, &["problem", "evidence", "change", "predicted", "why"])?;
            address(o, "problem")?;
            list(o, "evidence", "addresses", Address::parse)?;
            numbers(o, "change")?;
            numbers(o, "predicted")?;
            if o["change"].as_object().is_some_and(Map::is_empty) {
                return Err("`change` must change at least one parameter".into());
            }
            text(o, "why")
        }
        Kind::Decision => {
            exact(o, &["proposal", "verdict", "effective", "why"])?;
            address(o, "proposal")?;
            text(o, "why")?;
            match (o["verdict"].as_str(), &o["effective"]) {
                (Some("approve"), Value::Number(n)) if n.as_u64().is_some() => Ok(()),
                (Some("reject"), Value::Null) => Ok(()),
                (Some("approve"), _) => {
                    Err("an approval's `effective` must be a round or epoch number".into())
                }
                (Some("reject"), _) => Err("a rejection's `effective` must be null".into()),
                _ => Err("`verdict` must be `approve` or `reject`".into()),
            }
        }
        Kind::Attempt => {
            exact(o, &["problem", "decision", "rules", "runner", "predicted"])?;
            address(o, "problem")?;
            if !o["decision"].is_null() {
                address(o, "decision")?;
            }
            numbers(o, "rules")?;
            numbers(o, "predicted")?;
            runner(
                o["runner"]
                    .as_object()
                    .ok_or("`runner` must be an object")?,
            )
        }
        Kind::Outcome => {
            exact(o, &["attempt", "observed", "runs", "spread", "artifacts"])?;
            address(o, "attempt")?;
            numbers(o, "observed")?;
            list(o, "artifacts", "addresses", Address::parse)?;
            let runs = o["runs"]
                .as_u64()
                .filter(|r| *r >= 1)
                .ok_or("`runs` must be at least 1")?;
            let spread = o["spread"]
                .as_object()
                .ok_or("`spread` must be an object")?;
            if runs == 1 && !spread.is_empty() {
                return Err("`spread` must be {} when `runs` is 1".into());
            }
            for (m, v) in spread {
                let pair = v
                    .as_array()
                    .filter(|a| a.len() == 2)
                    .and_then(|a| Some((a[0].as_i64()?, a[1].as_i64()?)));
                match pair {
                    Some((lo, hi)) if lo <= hi => {}
                    _ => return Err(format!("`spread` for `{m}` must be [low, high]")),
                }
            }
            Ok(())
        }
    }
}

/// The runner of section 5.
fn runner(o: &Map<String, Value>) -> Result<(), String> {
    exact(
        o,
        &["kind", "name", "version", "weights", "params", "prompt"],
    )?;
    if !matches!(o["kind"].as_str(), Some("scripted" | "model" | "human")) {
        return Err("runner `kind` must be `scripted`, `model` or `human`".into());
    }
    text(o, "name")?;
    text(o, "version")?;
    numbers(o, "params")?;
    for m in ["weights", "prompt"] {
        if !o[m].is_null() {
            address(o, m)?;
        }
    }
    Ok(())
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 1 || !is_lower_hex(s) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

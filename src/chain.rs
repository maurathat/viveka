//! Verifying a chain: SPEC.md section 6, rules V1 to V9.

use crate::record::{Address, Key, Kind, Record, RecordError, Signed, Signer};
use crate::store::{Store, StoreError};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A chain refused at one record, with the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Position of the record in the chain.
    pub seq: u64,
    /// The rule of section 6, `V1` to `V9`.
    pub rule: &'static str,
    /// What was wrong.
    pub why: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "record {} breaks {}: {}", self.seq, self.rule, self.why)
    }
}

impl std::error::Error for Violation {}

/// Where a proposal stands (section 6, last paragraph).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalState {
    /// Fewer than `quorum` approvals so far, and no rejection.
    Pending,
    /// `quorum` distinct approvers approved before anyone rejected.
    Approved,
    /// An approver rejected it before it was approved.
    Rejected,
}

/// A verified chain and what it has decided.
#[derive(Debug, Clone)]
pub struct Chain {
    records: Vec<Signed>,
    index: BTreeMap<Address, usize>,
    state: BTreeMap<Address, ProposalState>,
    /// Approved proposals with the decision that completed each quorum, in
    /// the order they completed.
    completed: Vec<(Address, usize)>,
}

impl Chain {
    /// The records, genesis first.
    pub fn records(&self) -> &[Signed] {
        &self.records
    }
    /// The genesis record.
    pub fn genesis(&self) -> &Record {
        &self.records[0].record
    }
    /// The newest record's address.
    pub fn head(&self) -> &Address {
        &self.records[self.records.len() - 1].address
    }
    /// The record stored under `a`.
    pub fn get(&self, a: &Address) -> Option<&Signed> {
        self.index.get(a).map(|i| &self.records[*i])
    }
    /// Every proposal with its state, oldest first.
    pub fn proposals(&self) -> Vec<(&Signed, ProposalState)> {
        self.records
            .iter()
            .filter(|s| s.record.kind == Kind::Proposal)
            .map(|s| (s, self.state[&s.address]))
            .collect()
    }
    /// The state of the proposal at `a`.
    pub fn proposal_state(&self, a: &Address) -> Option<ProposalState> {
        self.state.get(a).copied()
    }

    /// The parameters in force for round or epoch `at`: each approved
    /// proposal's change, applied in the order the approvals completed, from
    /// its decision's `effective` onward. Parameters no approval has touched
    /// are absent; their values are the system's own defaults.
    pub fn rules_at(&self, at: u64) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        for (proposal, decision) in &self.completed {
            // The decision that completed the quorum says when it applies.
            let effective = self.records[*decision].record.body["effective"].as_u64();
            if !effective.is_some_and(|e| e <= at) {
                continue;
            }
            if let Some(change) = self
                .get(proposal)
                .and_then(|r| r.record.body["change"].as_object())
            {
                for (k, v) in change {
                    out.insert(k.clone(), v.as_i64().unwrap_or(0));
                }
            }
        }
        out
    }

    /// Sign and add a record of `kind` with `body`, verifying the whole
    /// chain with it before anything is written to `store`.
    pub fn append(
        &mut self,
        store: &mut dyn Store,
        signer: &Signer,
        kind: Kind,
        body: Map<String, Value>,
        time: i64,
    ) -> Result<Address, AppendError> {
        let g = self.genesis();
        let record = Record::new(
            kind,
            &g.chain,
            self.records.len() as u64,
            Some(self.head().clone()),
            signer.key(),
            time,
            body,
        )?;
        let signed = signer.sign(record)?;
        let mut all = self.records.clone();
        all.push(signed.clone());
        *self = verify(all)?;
        store.put(&signed.record.chain, &signed.address, &signed.to_bytes())?;
        store.set_head(&signed.record.chain, &signed.address)?;
        Ok(signed.address)
    }

    /// Start a chain: sign a genesis record and write it to `store`.
    pub fn start(
        store: &mut dyn Store,
        signer: &Signer,
        chain: &str,
        body: Map<String, Value>,
        time: i64,
    ) -> Result<Chain, AppendError> {
        if store.head(chain)?.is_some() {
            return Err(AppendError::Exists(chain.to_string()));
        }
        let signed = signer.sign(Record::new(
            Kind::Genesis,
            chain,
            0,
            None,
            signer.key(),
            time,
            body,
        )?)?;
        let out = verify(vec![signed.clone()])?;
        store.put(chain, &signed.address, &signed.to_bytes())?;
        store.set_head(chain, &signed.address)?;
        Ok(out)
    }

    /// Load `chain` from `store` by walking back from its head, checking
    /// every record's bytes against the address it is stored under (V2) and
    /// its signature (V3), then verifying the chain.
    pub fn load(store: &dyn Store, chain: &str) -> Result<Chain, LoadError> {
        let mut next = Some(
            store
                .head(chain)?
                .ok_or_else(|| LoadError::NoChain(chain.to_string()))?,
        );
        let mut records = Vec::new();
        while let Some(a) = next {
            let bytes = store
                .get(chain, &a)?
                .ok_or_else(|| LoadError::Missing(a.clone()))?;
            let signed = Signed::from_bytes(&bytes).map_err(|e| LoadError::Record(a.clone(), e))?;
            if signed.address != a {
                return Err(LoadError::WrongAddress {
                    stored: a,
                    actual: signed.address,
                });
            }
            if signed.record.chain != chain {
                return Err(LoadError::Record(
                    a,
                    RecordError::Envelope("record belongs to another chain".into()),
                ));
            }
            // `seq` must fall by one each step back, so a parent loop ends.
            if records
                .last()
                .is_some_and(|l: &Signed| l.record.seq != signed.record.seq + 1)
            {
                return Err(LoadError::Chain(Violation {
                    seq: signed.record.seq,
                    rule: "V4",
                    why: "`seq` does not fall by one toward the genesis".into(),
                }));
            }
            next = signed.record.parent.clone();
            records.push(signed);
        }
        records.reverse();
        Ok(verify(records)?)
    }
}

/// Why a record could not be added.
#[derive(Debug)]
pub enum AppendError {
    Record(RecordError),
    Chain(Violation),
    Store(StoreError),
    /// A chain of this name already exists in the store.
    Exists(String),
}

impl fmt::Display for AppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppendError::Record(e) => write!(f, "{e}"),
            AppendError::Chain(e) => write!(f, "{e}"),
            AppendError::Store(e) => write!(f, "{e}"),
            AppendError::Exists(c) => write!(f, "chain `{c}` already exists"),
        }
    }
}

impl std::error::Error for AppendError {}

impl From<RecordError> for AppendError {
    fn from(e: RecordError) -> Self {
        AppendError::Record(e)
    }
}
impl From<Violation> for AppendError {
    fn from(e: Violation) -> Self {
        AppendError::Chain(e)
    }
}
impl From<StoreError> for AppendError {
    fn from(e: StoreError) -> Self {
        AppendError::Store(e)
    }
}

/// Why a chain could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The store has no chain of this name.
    NoChain(String),
    /// A record the chain names is not in the store.
    Missing(Address),
    /// The bytes stored under an address are a different record (V2).
    WrongAddress {
        stored: Address,
        actual: Address,
    },
    /// A stored record is malformed or its signature fails (V1, V3).
    Record(Address, RecordError),
    Chain(Violation),
    Store(StoreError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::NoChain(c) => write!(f, "no chain `{c}` in this store"),
            LoadError::Missing(a) => {
                write!(f, "record {a} is named by the chain but not in the store")
            }
            LoadError::WrongAddress { stored, actual } => write!(
                f,
                "breaks V2: the bytes stored under {stored} have address {actual}"
            ),
            LoadError::Record(a, e) => write!(f, "record {a}: {e}"),
            LoadError::Chain(e) => write!(f, "{e}"),
            LoadError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<Violation> for LoadError {
    fn from(e: Violation) -> Self {
        LoadError::Chain(e)
    }
}
impl From<StoreError> for LoadError {
    fn from(e: StoreError) -> Self {
        LoadError::Store(e)
    }
}

/// Verify `records`, genesis first, under rules V1 and V4 to V9. Each
/// `Signed` already carries a recomputed address and a checked signature when
/// it came from [`Signed::from_bytes`] or [`Signer::sign`] (V2, V3).
pub fn verify(records: Vec<Signed>) -> Result<Chain, Violation> {
    let bad = |seq: u64, rule: &'static str, why: String| Violation { seq, rule, why };
    let mut index: BTreeMap<Address, usize> = BTreeMap::new();
    let mut approvals: BTreeMap<Address, BTreeSet<Key>> = BTreeMap::new();
    let mut state: BTreeMap<Address, ProposalState> = BTreeMap::new();
    let mut completed: Vec<(Address, usize)> = Vec::new();
    let first = records
        .first()
        .ok_or_else(|| bad(0, "V4", "a chain has at least a genesis record".into()))?;
    let (chain, writers, approvers, scope) = (
        first.record.chain.clone(),
        first.record.keys_in("writers"),
        first.record.keys_in("approvers"),
        first.record.strings_in("scope"),
    );
    let quorum = first
        .record
        .body
        .get("quorum")
        .and_then(Value::as_u64)
        .unwrap_or(1) as usize;

    for (i, s) in records.iter().enumerate() {
        let (r, seq) = (&s.record, i as u64);
        // V1
        r.check().map_err(|e| bad(seq, "V1", e.to_string()))?;
        // V4
        let want_parent = i.checked_sub(1).map(|p| records[p].address.clone());
        if r.seq != seq || r.parent != want_parent || r.chain != chain {
            return Err(bad(
                seq,
                "V4",
                "`seq`, `parent` or `chain` does not follow the record before it".into(),
            ));
        }
        // V5
        if !writers.contains(&r.author) {
            return Err(bad(
                seq,
                "V5",
                format!("author {} is not a writer of this chain", r.author),
            ));
        }
        // V6: a body's address names an earlier record of the kind required.
        let earlier = |member: &str, kind: Kind| -> Result<&Signed, Violation> {
            let a = r
                .address_in(member)
                .ok_or_else(|| bad(seq, "V6", format!("`{member}` is not an address")))?;
            match index.get(&a).map(|j| &records[*j]) {
                Some(t) if t.record.kind == kind => Ok(t),
                Some(_) => Err(bad(
                    seq,
                    "V6",
                    format!("`{member}` names a record that is not a {}", kind.name()),
                )),
                None => Err(bad(
                    seq,
                    "V6",
                    format!("`{member}` names no earlier record of this chain"),
                )),
            }
        };
        let measures_of = |problem: &Signed| problem.record.strings_in("measures");
        let within = |member: &str, allowed: &[String], what: &str| -> Result<(), Violation> {
            match r.body[member]
                .as_object()
                .and_then(|o| o.keys().find(|k| !allowed.contains(k)))
            {
                Some(k) => Err(bad(
                    seq,
                    "V9",
                    format!("`{member}` names `{k}`, which is not {what}"),
                )),
                None => Ok(()),
            }
        };
        match r.kind {
            Kind::Genesis | Kind::Problem => {}
            Kind::Proposal => {
                let problem = earlier("problem", Kind::Problem)?;
                for e in r.strings_in("evidence") {
                    if !Address::parse(&e).is_some_and(|a| index.contains_key(&a)) {
                        return Err(bad(
                            seq,
                            "V6",
                            format!("evidence {e} is no earlier record of this chain"),
                        ));
                    }
                }
                // V7
                if let Some(k) = r.body["change"]
                    .as_object()
                    .and_then(|o| o.keys().find(|k| !scope.contains(k)))
                {
                    return Err(bad(
                        seq,
                        "V7",
                        format!("`{k}` is outside the scope this chain's genesis allows"),
                    ));
                }
                within(
                    "predicted",
                    &measures_of(problem),
                    "a measure of its problem",
                )?;
                state.insert(s.address.clone(), ProposalState::Pending);
            }
            Kind::Decision => {
                let p = earlier("proposal", Kind::Proposal)?.address.clone();
                if !approvers.contains(&r.author) {
                    return Err(bad(
                        seq,
                        "V5",
                        format!("author {} is not an approver of this chain", r.author),
                    ));
                }
                if state[&p] == ProposalState::Pending {
                    if r.body["verdict"] == "reject" {
                        state.insert(p, ProposalState::Rejected);
                    } else {
                        let who = approvals.entry(p.clone()).or_default();
                        who.insert(r.author.clone());
                        if who.len() >= quorum {
                            state.insert(p.clone(), ProposalState::Approved);
                            completed.push((p, i));
                        }
                    }
                }
            }
            Kind::Attempt => {
                let problem = earlier("problem", Kind::Problem)?;
                within(
                    "predicted",
                    &measures_of(problem),
                    "a measure of its problem",
                )?;
                let rules = r.body["rules"].as_object().cloned().unwrap_or_default();
                if let Some(missing) = scope.iter().find(|p| !rules.contains_key(*p)) {
                    return Err(bad(
                        seq,
                        "V8",
                        format!("`rules` gives no value for `{missing}`"),
                    ));
                }
                if let Some(extra) = rules.keys().find(|k| !scope.contains(k)) {
                    return Err(bad(
                        seq,
                        "V8",
                        format!("`rules` names `{extra}`, which is outside the chain's scope"),
                    ));
                }
                // V8
                if !r.body["decision"].is_null() {
                    let d = earlier("decision", Kind::Decision)?;
                    let p = d
                        .record
                        .address_in("proposal")
                        .expect("checked when the decision was admitted");
                    if d.record.body["verdict"] != "approve" || state[&p] != ProposalState::Approved
                    {
                        return Err(bad(
                            seq,
                            "V8",
                            "the decision it names is not an approval of an approved proposal"
                                .into(),
                        ));
                    }
                    let change = records[index[&p]].record.body["change"]
                        .as_object()
                        .cloned()
                        .unwrap_or_default();
                    if let Some((k, _)) = change.iter().find(|(k, v)| rules.get(*k) != Some(*v)) {
                        return Err(bad(
                            seq,
                            "V8",
                            format!("`rules` does not run the approved value of `{k}`"),
                        ));
                    }
                }
            }
            Kind::Outcome => {
                let attempt = earlier("attempt", Kind::Attempt)?;
                let problem = &records[index[&attempt
                    .record
                    .address_in("problem")
                    .expect("checked when the attempt was admitted")]];
                let measures = measures_of(problem);
                // V9
                let observed = r.body["observed"].as_object().cloned().unwrap_or_default();
                if let Some(m) = measures.iter().find(|m| !observed.contains_key(*m)) {
                    return Err(bad(seq, "V9", format!("`observed` does not report `{m}`")));
                }
                within("observed", &measures, "a measure of its problem")?;
                within("spread", &measures, "a measure of its problem")?;
            }
        }
        index.insert(s.address.clone(), i);
    }
    Ok(Chain {
        records,
        index,
        state,
        completed,
    })
}

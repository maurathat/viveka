//! One test per rule of SPEC.md: the input rules of section 2 and the
//! verification rules V1 to V9 of section 6, each with a record that breaks
//! it and the refusal naming it.

use serde_json::{Map, Value, json};
use viveka::chain::{AppendError, LoadError};
use viveka::json::{InputError, parse};
use viveka::record::RecordError;
use viveka::{
    Address, Chain, FolderStore, Kind, MemStore, ProposalState, Record, Signed, Signer, Store,
    verify,
};

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

struct World {
    store: MemStore,
    chain: Chain,
    writer: Signer,
    approver: Signer,
    second: Signer,
    t: i64,
}

impl World {
    fn new(quorum: u64) -> World {
        let (writer, approver, second) = (
            Signer::generate().unwrap(),
            Signer::generate().unwrap(),
            Signer::generate().unwrap(),
        );
        let mut store = MemStore::default();
        let body = obj(json!({
            "writers": [writer.key().as_str(), approver.key().as_str(), second.key().as_str()],
            "approvers": [approver.key().as_str(), second.key().as_str()],
            "quorum": quorum,
            "scope": ["canary_permille", "panel_k"],
            "purpose": "test market",
        }));
        let chain = Chain::start(&mut store, &writer, "test-market", body, 1000).unwrap();
        World {
            store,
            chain,
            writer,
            approver,
            second,
            t: 1000,
        }
    }
    fn add_as(&mut self, who: u8, kind: Kind, body: Value) -> Result<Address, AppendError> {
        self.t += 1;
        let signer = [&self.writer, &self.approver, &self.second][who as usize];
        self.chain
            .append(&mut self.store, signer, kind, obj(body), self.t)
    }
    fn add(&mut self, kind: Kind, body: Value) -> Address {
        self.add_as(0, kind, body).unwrap()
    }
    fn refused(&mut self, who: u8, kind: Kind, body: Value) -> String {
        match self.add_as(who, kind, body) {
            Err(AppendError::Chain(v)) => v.rule.to_string(),
            Err(e) => format!("{e}"),
            Ok(_) => "admitted".to_string(),
        }
    }
    fn problem(&mut self) -> Address {
        self.add(
            Kind::Problem,
            json!({"title": "junk sellers linger", "measures": ["caught", "false_alarms"]}),
        )
    }
    fn proposal(&mut self, problem: &Address) -> Address {
        self.add(Kind::Proposal, json!({"problem": problem.as_str(), "evidence": [problem.as_str()], "change": {"canary_permille": 160}, "predicted": {"caught": 9}, "why": "more tests"}))
    }
    fn approve(&mut self, who: u8, proposal: &Address, effective: u64) -> Address {
        self.add_as(who, Kind::Decision, json!({"proposal": proposal.as_str(), "verdict": "approve", "effective": effective, "why": "evidence holds"})).unwrap()
    }
}

fn runner() -> Value {
    json!({"kind": "scripted", "name": "kx-sim", "version": "88d8bea", "weights": null, "params": {"seed": 7}, "prompt": null})
}

fn attempt(problem: &Address, decision: Option<&Address>, canary: i64) -> Value {
    json!({"problem": problem.as_str(), "decision": decision.map(|d| d.as_str()), "rules": {"canary_permille": canary, "panel_k": 4}, "runner": runner(), "predicted": {"caught": 9}})
}

#[test]
fn the_address_is_uor_addrs() {
    // The vector uor-addr's Python binding documents: the same bytes, the
    // same label, in every language.
    let a = Address::of(&json!({"foo": "bar"})).unwrap();
    assert_eq!(
        a.as_str(),
        "blake3:16b6abe0a77021b88cc14863d696df0c34f82556faadb318f46c384184f8ea71"
    );
    // Member order does not change an address.
    assert_eq!(
        Address::of(&parse(br#"{"b":1,"a":2}"#).unwrap()).unwrap(),
        Address::of(&parse(br#"{"a":2,"b":1}"#).unwrap()).unwrap()
    );
}

#[test]
fn input_rules_of_section_2() {
    assert!(matches!(
        parse(br#"{"a": 1.5}"#),
        Err(InputError::Number(_))
    ));
    assert!(matches!(
        parse(br#"{"a": 1.0}"#),
        Err(InputError::Number(_))
    ));
    assert!(matches!(
        parse(br#"{"a": 1e2}"#),
        Err(InputError::Number(_))
    ));
    assert!(matches!(
        parse(br#"{"a": 9007199254740992}"#),
        Err(InputError::Number(_))
    ));
    assert!(parse(br#"{"a": 9007199254740991}"#).is_ok());
    // "e" followed by a combining acute accent is not NFC; U+00E9 is.
    assert!(matches!(
        parse("{\"a\": \"e\u{301}\"}".as_bytes()),
        Err(InputError::NotNfc(_))
    ));
    assert!(matches!(
        parse("{\"e\u{301}\": 1}".as_bytes()),
        Err(InputError::NotNfc(_))
    ));
    assert!(parse("{\"a\": \"\u{e9}\"}".as_bytes()).is_ok());
    assert!(matches!(
        parse(br#"{"a": 1, "a": 2}"#),
        Err(InputError::DuplicateName(_))
    ));
    assert!(matches!(
        parse(br#"{"a": 1} x"#),
        Err(InputError::Syntax(_))
    ));
}

#[test]
fn a_whole_loop_verifies_and_reloads() {
    let mut w = World::new(1);
    let p = w.problem();
    let base = w.add(Kind::Attempt, attempt(&p, None, 80));
    let o = w.add(Kind::Outcome, json!({"attempt": base.as_str(), "observed": {"caught": 4, "false_alarms": 0}, "runs": 20, "spread": {"caught": [2, 6]}, "artifacts": []}));
    let prop = w.add(Kind::Proposal, json!({"problem": p.as_str(), "evidence": [o.as_str()], "change": {"canary_permille": 160}, "predicted": {"caught": 9}, "why": "more tests"}));
    assert_eq!(w.chain.proposal_state(&prop), Some(ProposalState::Pending));
    assert!(w.chain.rules_at(99).is_empty());
    let d = w.approve(1, &prop, 5);
    assert_eq!(w.chain.proposal_state(&prop), Some(ProposalState::Approved));
    // In force from its effective round, not before.
    assert!(w.chain.rules_at(4).is_empty());
    assert_eq!(w.chain.rules_at(5).get("canary_permille"), Some(&160));
    let a2 = w.add(Kind::Attempt, attempt(&p, Some(&d), 160));
    w.add(Kind::Outcome, json!({"attempt": a2.as_str(), "observed": {"caught": 8, "false_alarms": 1}, "runs": 1, "spread": {}, "artifacts": []}));
    let again = Chain::load(&w.store, "test-market").unwrap();
    assert_eq!(again.head(), w.chain.head());
    assert_eq!(again.records().len(), 8);
}

#[test]
fn v1_a_malformed_record_is_refused() {
    let mut w = World::new(1);
    assert!(
        w.refused(0, Kind::Problem, json!({"title": "x"}))
            .contains("missing member `measures`")
    );
    assert!(
        w.refused(
            0,
            Kind::Problem,
            json!({"title": "x", "measures": ["a"], "extra": 1})
        )
        .contains("unknown member `extra`")
    );
    let p = w.problem();
    let mut bad = attempt(&p, None, 80);
    bad["runner"]["kind"] = json!("oracle");
    assert!(w.refused(0, Kind::Attempt, bad).contains("runner `kind`"));
}

#[test]
fn v2_bytes_under_the_wrong_address_are_refused() {
    let mut w = World::new(1);
    let p = w.problem();
    let other = w.add(
        Kind::Problem,
        json!({"title": "another", "measures": ["m"]}),
    );
    // Put the first problem's bytes where the second's should be.
    let bytes = w.store.get("test-market", &p).unwrap().unwrap();
    w.store
        .records
        .insert(("test-market".into(), other.clone()), bytes);
    assert!(matches!(
        Chain::load(&w.store, "test-market"),
        Err(LoadError::WrongAddress { .. })
    ));
}

#[test]
fn v3_a_changed_record_or_signature_is_refused() {
    let mut w = World::new(1);
    let p = w.problem();
    let bytes = w.store.get("test-market", &p).unwrap().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    // One word of the record changed: the signature no longer covers it.
    let changed = text.replace("junk sellers linger", "junk sellers leave");
    assert_eq!(
        Signed::from_bytes(changed.as_bytes()),
        Err(RecordError::Signature)
    );
    // A signature by a key other than the author.
    let stranger = Signer::generate().unwrap();
    let mut forged = Signed::from_bytes(text.as_bytes()).unwrap();
    let mut r = forged.record.clone();
    r.author = stranger.key();
    forged.sig = stranger.sign(r).unwrap().sig;
    assert_eq!(
        Signed::from_bytes(&forged.to_bytes()),
        Err(RecordError::Signature)
    );
}

#[test]
fn v4_a_record_out_of_place_is_refused() {
    let mut w = World::new(1);
    w.problem();
    w.add(
        Kind::Problem,
        json!({"title": "another", "measures": ["m"]}),
    );
    let mut records = w.chain.records().to_vec();
    // Drop the middle record: the last no longer follows its parent.
    records.remove(1);
    assert_eq!(verify(records).unwrap_err().rule, "V4");
    // The right position but the wrong parent: a record at 2 that names the
    // genesis, not record 1, as the record before it.
    let mut records = w.chain.records()[..2].to_vec();
    let stray = Record::new(
        Kind::Problem,
        "test-market",
        2,
        Some(records[0].address.clone()),
        w.writer.key(),
        5,
        obj(json!({"title": "stray", "measures": ["m"]})),
    )
    .unwrap();
    records.push(w.writer.sign(stray).unwrap());
    assert_eq!(verify(records).unwrap_err().rule, "V4");
    // A second genesis cannot follow the first.
    let g = w.chain.genesis().body.clone();
    assert!(
        w.refused(0, Kind::Genesis, Value::Object(g))
            .contains("record 0")
    );
}

#[test]
fn v5_only_writers_write_and_only_approvers_decide() {
    let mut w = World::new(1);
    let p = w.problem();
    let prop = w.proposal(&p);
    // The writer is not an approver.
    assert_eq!(
        w.refused(
            0,
            Kind::Decision,
            json!({"proposal": prop.as_str(), "verdict": "approve", "effective": 2, "why": "mine"})
        ),
        "V5"
    );
    // A stranger is not a writer.
    let stranger = Signer::generate().unwrap();
    let err = w.chain.append(
        &mut w.store,
        &stranger,
        Kind::Problem,
        obj(json!({"title": "x", "measures": ["m"]})),
        2000,
    );
    assert!(matches!(err, Err(AppendError::Chain(v)) if v.rule == "V5"));
}

#[test]
fn v6_a_body_names_only_earlier_records_of_the_right_kind() {
    let mut w = World::new(1);
    let p = w.problem();
    let nowhere = Address::of(&json!({"not": "in the chain"})).unwrap();
    assert_eq!(w.refused(0, Kind::Proposal, json!({"problem": nowhere.as_str(), "evidence": [], "change": {"panel_k": 5}, "predicted": {}, "why": "x"})), "V6");
    assert_eq!(w.refused(0, Kind::Proposal, json!({"problem": p.as_str(), "evidence": [nowhere.as_str()], "change": {"panel_k": 5}, "predicted": {}, "why": "x"})), "V6");
    // An outcome must name an attempt, not a problem.
    assert_eq!(
        w.refused(
            0,
            Kind::Outcome,
            json!({"attempt": p.as_str(), "observed": {}, "runs": 1, "spread": {}, "artifacts": []})
        ),
        "V6"
    );
}

#[test]
fn v7_a_proposal_stays_inside_the_scope() {
    let mut w = World::new(1);
    let p = w.problem();
    assert_eq!(w.refused(0, Kind::Proposal, json!({"problem": p.as_str(), "evidence": [], "change": {"ladder_step": 3}, "predicted": {}, "why": "x"})), "V7");
}

#[test]
fn v8_an_attempt_runs_only_an_approved_change() {
    let mut w = World::new(2);
    let p = w.problem();
    let prop = w.proposal(&p);
    // One approval of a quorum of two: not yet approved.
    let d1 = w.approve(1, &prop, 3);
    assert_eq!(w.chain.proposal_state(&prop), Some(ProposalState::Pending));
    assert_eq!(
        w.refused(0, Kind::Attempt, attempt(&p, Some(&d1), 160)),
        "V8"
    );
    // The same approver twice is still one approver.
    w.approve(1, &prop, 3);
    assert_eq!(w.chain.proposal_state(&prop), Some(ProposalState::Pending));
    let d2 = w.approve(2, &prop, 3);
    assert_eq!(w.chain.proposal_state(&prop), Some(ProposalState::Approved));
    // It must run the approved value, and name every parameter in scope.
    assert_eq!(
        w.refused(0, Kind::Attempt, attempt(&p, Some(&d2), 80)),
        "V8"
    );
    assert_eq!(w.refused(0, Kind::Attempt, json!({"problem": p.as_str(), "decision": null, "rules": {"canary_permille": 80}, "runner": runner(), "predicted": {}})), "V8");
    w.add(Kind::Attempt, attempt(&p, Some(&d2), 160));

    // A rejection before the quorum ends the proposal for good.
    let other = w.proposal(&p);
    let no = w.add_as(1, Kind::Decision, json!({"proposal": other.as_str(), "verdict": "reject", "effective": null, "why": "evidence is one run"})).unwrap();
    let late = w.approve(2, &other, 9);
    w.approve(1, &other, 9);
    assert_eq!(
        w.chain.proposal_state(&other),
        Some(ProposalState::Rejected)
    );
    assert_eq!(
        w.refused(0, Kind::Attempt, attempt(&p, Some(&late), 160)),
        "V8"
    );
    assert_eq!(
        w.refused(0, Kind::Attempt, attempt(&p, Some(&no), 160)),
        "V8"
    );
}

#[test]
fn v9_an_outcome_reports_every_measure_of_its_problem() {
    let mut w = World::new(1);
    let p = w.problem();
    let a = w.add(Kind::Attempt, attempt(&p, None, 80));
    assert_eq!(w.refused(0, Kind::Outcome, json!({"attempt": a.as_str(), "observed": {"caught": 4}, "runs": 1, "spread": {}, "artifacts": []})), "V9");
    assert_eq!(w.refused(0, Kind::Outcome, json!({"attempt": a.as_str(), "observed": {"caught": 4, "false_alarms": 0, "profit": 3}, "runs": 1, "spread": {}, "artifacts": []})), "V9");
}

#[test]
fn the_folder_store_keeps_the_layout_of_section_7() {
    let dir = std::env::temp_dir().join(format!("viveka-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut store = FolderStore::new(&dir);
    let signer = Signer::generate().unwrap();
    let body = obj(
        json!({"writers": [signer.key().as_str()], "approvers": [signer.key().as_str()], "quorum": 1, "scope": [], "purpose": "folder"}),
    );
    let mut chain = Chain::start(&mut store, &signer, "folder-test", body.clone(), 1).unwrap();
    let p = chain
        .append(
            &mut store,
            &signer,
            Kind::Problem,
            obj(json!({"title": "t", "measures": ["m"]})),
            2,
        )
        .unwrap();
    assert!(
        dir.join("folder-test/records")
            .join(format!("{}.json", p.hex()))
            .is_file()
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("folder-test/HEAD"))
            .unwrap()
            .trim(),
        p.as_str()
    );
    assert_eq!(Chain::load(&store, "folder-test").unwrap().head(), &p);
    // A chain is started once.
    assert!(matches!(
        Chain::start(&mut store, &signer, "folder-test", body, 3),
        Err(AppendError::Exists(_))
    ));
    // A name that could leave the folder is refused.
    assert!(store.head("../elsewhere").is_err());
    assert!(matches!(
        Chain::load(&store, "absent"),
        Err(LoadError::NoChain(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

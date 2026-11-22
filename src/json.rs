//! The input rules of SPEC.md section 2: strict JSON in, or a refusal.
//!
//! `serde_json` alone would keep the last of two members with one name and
//! accept any number; a record must be refused for either, never repaired.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;
use unicode_normalization::{UnicodeNormalization, is_nfc};

/// Largest whole number a record may carry: 2^53 - 1.
pub const MAX_INT: i64 = (1 << 53) - 1;

/// Why input was refused under section 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    /// Not JSON at all, or trailing bytes after the value.
    Syntax(String),
    /// A number that is not a whole number in range (rule 1).
    Number(String),
    /// A string or member name not in Unicode NFC form (rule 2).
    NotNfc(String),
    /// Two members of one object with the same name (rule 3).
    DuplicateName(String),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Syntax(m) => write!(f, "not valid JSON: {m}"),
            InputError::Number(n) => {
                write!(f, "number {n} is not a whole number within ±(2^53 - 1)")
            }
            InputError::NotNfc(s) => write!(f, "text {s:?} is not in Unicode NFC form"),
            InputError::DuplicateName(n) => {
                write!(f, "member name {n:?} appears twice in one object")
            }
        }
    }
}

impl std::error::Error for InputError {}

/// Parse `bytes` as one JSON value under the input rules.
pub fn parse(bytes: &[u8]) -> Result<Value, InputError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = Strict.deserialize(&mut de).map_err(classify)?;
    de.end().map_err(|e| InputError::Syntax(e.to_string()))?;
    Ok(v)
}

/// Check a value built in memory against the same rules.
pub fn check(v: &Value) -> Result<(), InputError> {
    match v {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(n) => whole(n).map(|_| ()),
        Value::String(s) => nfc(s),
        Value::Array(a) => a.iter().try_for_each(check),
        Value::Object(m) => {
            let mut seen = std::collections::BTreeSet::new();
            for (k, v) in m {
                nfc(k)?;
                if !seen.insert(k.nfc().collect::<String>()) {
                    return Err(InputError::DuplicateName(k.clone()));
                }
                check(v)?;
            }
            Ok(())
        }
    }
}

fn nfc(s: &str) -> Result<(), InputError> {
    if is_nfc(s) {
        Ok(())
    } else {
        Err(InputError::NotNfc(s.to_string()))
    }
}

fn whole(n: &Number) -> Result<i64, InputError> {
    match n.as_i64() {
        Some(i) if (-MAX_INT..=MAX_INT).contains(&i) => Ok(i),
        _ => Err(InputError::Number(n.to_string())),
    }
}

// Errors raised inside the visitor travel as serde custom errors; the prefix
// carries which rule broke back out.
const TAG_NUMBER: &str = "viveka-number:";
const TAG_NFC: &str = "viveka-nfc:";
const TAG_DUP: &str = "viveka-dup:";

fn classify(e: serde_json::Error) -> InputError {
    let m = e.to_string();
    for (tag, make) in [
        (TAG_NUMBER, InputError::Number as fn(String) -> InputError),
        (TAG_NFC, InputError::NotNfc),
        (TAG_DUP, InputError::DuplicateName),
    ] {
        if let Some(i) = m.find(tag) {
            let rest = &m[i + tag.len()..];
            let end = rest.find(" at line ").unwrap_or(rest.len());
            return make(rest[..end].to_string());
        }
    }
    InputError::Syntax(m)
}

struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }
    fn visit_i64<E: de::Error>(self, i: i64) -> Result<Value, E> {
        whole(&Number::from(i)).map_err(|_| E::custom(format!("{TAG_NUMBER}{i}")))?;
        Ok(Value::Number(i.into()))
    }
    fn visit_u64<E: de::Error>(self, u: u64) -> Result<Value, E> {
        whole(&Number::from(u)).map_err(|_| E::custom(format!("{TAG_NUMBER}{u}")))?;
        Ok(Value::Number(u.into()))
    }
    fn visit_f64<E: de::Error>(self, x: f64) -> Result<Value, E> {
        // Any token with a fraction or exponent arrives here, 1.0 and 1e2 too.
        Err(E::custom(format!("{TAG_NUMBER}{x}")))
    }
    fn visit_str<E: de::Error>(self, s: &str) -> Result<Value, E> {
        if !is_nfc(s) {
            return Err(E::custom(format!("{TAG_NFC}{s}")));
        }
        Ok(Value::String(s.to_string()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(Strict)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if !is_nfc(&k) {
                return Err(de::Error::custom(format!("{TAG_NFC}{k}")));
            }
            if out.contains_key(&k) {
                return Err(de::Error::custom(format!("{TAG_DUP}{k}")));
            }
            let v = a.next_value_seed(Strict)?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

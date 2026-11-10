//! Result contracts (DESIGN.md §6). The conductor reads nothing else from a model's reply: exactly one
//! fenced block with the expected tag, holding strict JSON that echoes the prompt header. Anything
//! else is invalid, and an invalid result parks the cycle (§4 rule 2). Nothing defaults to `pass`.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::Agent;

pub const AUTHOR_SCHEMA: &str = "loop-cycle-author/1";
pub const VERDICT_SCHEMA: &str = "loop-cycle-verdict/1";
pub const AUTHOR_TAG: &str = "loop-cycle-author";
pub const VERDICT_TAG: &str = "loop-cycle-verdict";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Revise,
    Block,
}

/// What the conductor wrote into the prompt header, which the reply must echo.
#[derive(Clone, Debug)]
pub struct Header {
    pub cycle_id: String,
    pub phase: String,
    pub invocation_id: String,
    /// For an author: the digest of its input. For a reviewer: the frozen artifact's digest.
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorEstimate {
    pub complexity: u8,
    pub self_certainty: f64,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Review {
    pub reviewer: Agent,
    pub verdict: Verdict,
    pub certainty: f64,
    pub complexity: u8,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    NoBlock,
    SeveralBlocks(usize),
    WrongTag(String),
    Unterminated,
    DuplicateKey(String),
    Json(String),
    Schema(String),
    Mismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    OutOfRange {
        field: &'static str,
        value: String,
    },
    EmptyReasons,
    SelfReview(Agent),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::NoBlock => write!(f, "no result block"),
            ContractError::SeveralBlocks(n) => {
                write!(f, "{n} result blocks; exactly one is allowed")
            }
            ContractError::WrongTag(t) => write!(f, "result block tagged {t:?}"),
            ContractError::Unterminated => write!(f, "result block is not closed"),
            ContractError::DuplicateKey(k) => write!(f, "duplicate key {k:?}"),
            ContractError::Json(e) => write!(f, "invalid JSON: {e}"),
            ContractError::Schema(s) => write!(f, "schema {s:?} is not the expected one"),
            ContractError::Mismatch {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{field} is {actual:?}, expected {expected:?} (stale or copied result)"
                )
            }
            ContractError::OutOfRange { field, value } => {
                write!(f, "{field} {value} is out of range")
            }
            ContractError::EmptyReasons => write!(f, "reasons is empty"),
            ContractError::SelfReview(a) => write!(f, "{a:?} cannot review its own artifact"),
        }
    }
}

/// The body of the single fenced block whose info string is `tag`. Every fenced block tagged
/// `loop-cycle-…` counts, so a second block (or one with the other tag) makes the result invalid.
pub fn extract_block(reply: &str, tag: &str) -> Result<String, ContractError> {
    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut lines = reply.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let Some(info) = trimmed.strip_prefix("```") else {
            continue;
        };
        let info = info.trim();
        if !info.starts_with("loop-cycle-") {
            // Skip an unrelated fenced block whole, so its contents can't open a result block. A stray
            // fence swallows the rest of the reply, which can only hide a block (fail closed).
            for inner in lines.by_ref() {
                if inner.trim() == "```" {
                    break;
                }
            }
            continue;
        }
        let mut body = String::new();
        let mut closed = false;
        for inner in lines.by_ref() {
            if inner.trim() == "```" {
                closed = true;
                break;
            }
            body.push_str(inner);
            body.push('\n');
        }
        if !closed {
            return Err(ContractError::Unterminated);
        }
        blocks.push((info.to_string(), body));
    }
    match blocks.len() {
        0 => Err(ContractError::NoBlock),
        1 if blocks[0].0 == tag => Ok(blocks.remove(0).1),
        1 => Err(ContractError::WrongTag(blocks[0].0.clone())),
        n => Err(ContractError::SeveralBlocks(n)),
    }
}

/// Walks any JSON value and fails on a repeated key in any object.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDupVisitor)
    }
}

struct NoDupVisitor;

impl<'de> Visitor<'de> for NoDupVisitor {
    type Value = NoDuplicateKeys;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

fn strict<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, ContractError> {
    if let Err(e) = serde_json::from_str::<NoDuplicateKeys>(body) {
        let msg = e.to_string();
        return Err(match msg.strip_prefix("duplicate key ") {
            Some(rest) => ContractError::DuplicateKey(
                rest.split(" at line").next().unwrap_or(rest).to_string(),
            ),
            None => ContractError::Json(msg),
        });
    }
    serde_json::from_str::<T>(body).map_err(|e| ContractError::Json(e.to_string()))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorWire {
    schema: String,
    cycle_id: String,
    phase: String,
    invocation_id: String,
    input_sha256: String,
    complexity: u8,
    self_certainty: f64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictWire {
    schema: String,
    cycle_id: String,
    phase: String,
    invocation_id: String,
    artifact_sha256: String,
    verdict: Verdict,
    certainty: f64,
    complexity: u8,
    reasons: Vec<String>,
}

fn echo(field: &'static str, expected: &str, actual: &str) -> Result<(), ContractError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ContractError::Mismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

fn unit_interval(field: &'static str, v: f64) -> Result<(), ContractError> {
    if v.is_finite() && (0.0..=1.0).contains(&v) {
        Ok(())
    } else {
        Err(ContractError::OutOfRange {
            field,
            value: v.to_string(),
        })
    }
}

fn complexity(v: u8) -> Result<(), ContractError> {
    if (1..=5).contains(&v) {
        Ok(())
    } else {
        Err(ContractError::OutOfRange {
            field: "complexity",
            value: v.to_string(),
        })
    }
}

/// An author's result: its estimates for the artifact the conductor read from the output path.
pub fn parse_author(reply: &str, header: &Header) -> Result<AuthorEstimate, ContractError> {
    let w: AuthorWire = strict(&extract_block(reply, AUTHOR_TAG)?)?;
    if w.schema != AUTHOR_SCHEMA {
        return Err(ContractError::Schema(w.schema));
    }
    echo("cycle_id", &header.cycle_id, &w.cycle_id)?;
    echo("phase", &header.phase, &w.phase)?;
    echo("invocation_id", &header.invocation_id, &w.invocation_id)?;
    echo("input_sha256", &header.digest, &w.input_sha256)?;
    complexity(w.complexity)?;
    unit_interval("self_certainty", w.self_certainty)?;
    Ok(AuthorEstimate {
        complexity: w.complexity,
        self_certainty: w.self_certainty,
    })
}

/// A reviewer's result on the frozen artifact named in the header. `author` is the artifact's
/// author: a reviewer can never accept its own work.
pub fn parse_review(
    reply: &str,
    header: &Header,
    reviewer: Agent,
    author: Agent,
) -> Result<Review, ContractError> {
    if reviewer == author {
        return Err(ContractError::SelfReview(reviewer));
    }
    let w: VerdictWire = strict(&extract_block(reply, VERDICT_TAG)?)?;
    if w.schema != VERDICT_SCHEMA {
        return Err(ContractError::Schema(w.schema));
    }
    echo("cycle_id", &header.cycle_id, &w.cycle_id)?;
    echo("phase", &header.phase, &w.phase)?;
    echo("invocation_id", &header.invocation_id, &w.invocation_id)?;
    echo("artifact_sha256", &header.digest, &w.artifact_sha256)?;
    complexity(w.complexity)?;
    unit_interval("certainty", w.certainty)?;
    if w.reasons.is_empty() || w.reasons.iter().any(|r| r.trim().is_empty()) {
        return Err(ContractError::EmptyReasons);
    }
    Ok(Review {
        reviewer,
        verdict: w.verdict,
        certainty: w.certainty,
        complexity: w.complexity,
        reasons: w.reasons,
    })
}

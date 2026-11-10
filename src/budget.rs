//! Provider-neutral, fail-closed run-budget journal.
//!
//! The journal contains no credentials, prompts, or model output. A reservation is written and
//! synced before dispatch. Unknown cost leaves the reservation active and blocks later dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BUDGET_SCHEMA: &str = "loop-cycle-budget-journal/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostAuthority {
    Measured,
    Derived,
    DelayedReconciled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetEvent {
    Reserve {
        invocation_id: String,
        role_id: String,
        provider_id: String,
        model_id: String,
        reserved_usd_micros: u64,
    },
    Settle {
        invocation_id: String,
        settled_usd_micros: u64,
        authority: CostAuthority,
        request_id: String,
        reply_sha256: String,
    },
    CostUnknown {
        invocation_id: String,
        reason: String,
    },
    AbortBeforeDispatch {
        invocation_id: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub schema: String,
    pub seq: u64,
    pub at_unix_ms: u128,
    pub prev_sha256: String,
    pub event: BudgetEvent,
    pub entry_sha256: String,
}

#[derive(Serialize)]
struct EntryMaterial<'a> {
    schema: &'a str,
    seq: u64,
    at_unix_ms: u128,
    prev_sha256: &'a str,
    event: &'a BudgetEvent,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BudgetSnapshot {
    pub cap_usd_micros: u64,
    pub settled_usd_micros: u64,
    pub active_reserved_usd_micros: u64,
    pub remaining_usd_micros: u64,
    pub blocked: bool,
    pub entries: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BudgetError {
    Io(String),
    Invalid(String),
    Locked,
    Blocked,
    DuplicateInvocation(String),
    UnknownInvocation(String),
    CapExceeded {
        cap_usd_micros: u64,
        current_liability_usd_micros: u64,
        requested_usd_micros: u64,
    },
    Money(String),
}

impl From<std::io::Error> for BudgetError {
    fn from(value: std::io::Error) -> Self {
        BudgetError::Io(value.to_string())
    }
}

pub struct BudgetJournal {
    root: PathBuf,
    cap_usd_micros: u64,
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

impl BudgetJournal {
    pub fn new(root: impl Into<PathBuf>, cap_usd_micros: u64) -> Result<Self, BudgetError> {
        if cap_usd_micros == 0 {
            return Err(BudgetError::Invalid("budget cap must be positive".into()));
        }
        Ok(Self {
            root: root.into(),
            cap_usd_micros,
        })
    }

    fn events_path(&self) -> PathBuf {
        self.root.join("events.jsonl")
    }

    fn acquire(&self) -> Result<LockGuard, BudgetError> {
        fs::create_dir_all(&self.root)?;
        let path = self.root.join("journal.lock");
        match fs::create_dir(&path) {
            Ok(()) => Ok(LockGuard { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(BudgetError::Locked),
            Err(e) => Err(e.into()),
        }
    }

    pub fn snapshot(&self) -> Result<BudgetSnapshot, BudgetError> {
        let entries = read_and_verify(&self.events_path())?;
        summarize(&entries, self.cap_usd_micros)
    }

    pub fn reserve(
        &self,
        invocation_id: &str,
        role_id: &str,
        provider_id: &str,
        model_id: &str,
        reserved_usd_micros: u64,
    ) -> Result<BudgetSnapshot, BudgetError> {
        if reserved_usd_micros == 0 {
            return Err(BudgetError::Invalid("reservation must be positive".into()));
        }
        validate_id("invocation_id", invocation_id)?;
        validate_id("role_id", role_id)?;
        validate_id("provider_id", provider_id)?;
        validate_id("model_id", model_id)?;
        let _guard = self.acquire()?;
        let entries = read_and_verify(&self.events_path())?;
        let snapshot = summarize(&entries, self.cap_usd_micros)?;
        if snapshot.blocked {
            return Err(BudgetError::Blocked);
        }
        if entries
            .iter()
            .any(|e| event_invocation(&e.event) == invocation_id)
        {
            return Err(BudgetError::DuplicateInvocation(invocation_id.into()));
        }
        let current = snapshot
            .settled_usd_micros
            .checked_add(snapshot.active_reserved_usd_micros)
            .ok_or_else(|| BudgetError::Invalid("liability overflow".into()))?;
        if current
            .checked_add(reserved_usd_micros)
            .filter(|v| *v <= self.cap_usd_micros)
            .is_none()
        {
            return Err(BudgetError::CapExceeded {
                cap_usd_micros: self.cap_usd_micros,
                current_liability_usd_micros: current,
                requested_usd_micros: reserved_usd_micros,
            });
        }
        append(
            &self.events_path(),
            &entries,
            BudgetEvent::Reserve {
                invocation_id: invocation_id.into(),
                role_id: role_id.into(),
                provider_id: provider_id.into(),
                model_id: model_id.into(),
                reserved_usd_micros,
            },
        )?;
        self.snapshot()
    }

    pub fn settle(
        &self,
        invocation_id: &str,
        settled_usd_micros: u64,
        authority: CostAuthority,
        request_id: &str,
        reply_sha256: &str,
    ) -> Result<BudgetSnapshot, BudgetError> {
        validate_id("request_id", request_id)?;
        validate_sha256(reply_sha256)?;
        let _guard = self.acquire()?;
        let entries = read_and_verify(&self.events_path())?;
        require_active(&entries, invocation_id)?;
        append(
            &self.events_path(),
            &entries,
            BudgetEvent::Settle {
                invocation_id: invocation_id.into(),
                settled_usd_micros,
                authority,
                request_id: request_id.into(),
                reply_sha256: reply_sha256.to_ascii_lowercase(),
            },
        )?;
        self.snapshot()
    }

    pub fn cost_unknown(&self, invocation_id: &str, reason: &str) -> Result<(), BudgetError> {
        if reason.trim().is_empty() || reason.len() > 512 {
            return Err(BudgetError::Invalid(
                "unknown-cost reason is empty or too long".into(),
            ));
        }
        let _guard = self.acquire()?;
        let entries = read_and_verify(&self.events_path())?;
        require_active(&entries, invocation_id)?;
        append(
            &self.events_path(),
            &entries,
            BudgetEvent::CostUnknown {
                invocation_id: invocation_id.into(),
                reason: reason.into(),
            },
        )?;
        Ok(())
    }

    pub fn abort_before_dispatch(
        &self,
        invocation_id: &str,
        reason: &str,
    ) -> Result<BudgetSnapshot, BudgetError> {
        if reason.trim().is_empty() || reason.len() > 512 {
            return Err(BudgetError::Invalid(
                "abort reason is empty or too long".into(),
            ));
        }
        let _guard = self.acquire()?;
        let entries = read_and_verify(&self.events_path())?;
        require_active(&entries, invocation_id)?;
        append(
            &self.events_path(),
            &entries,
            BudgetEvent::AbortBeforeDispatch {
                invocation_id: invocation_id.into(),
                reason: reason.into(),
            },
        )?;
        self.snapshot()
    }
}

fn validate_id(field: &str, value: &str) -> Result<(), BudgetError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':'))
    {
        return Err(BudgetError::Invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), BudgetError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BudgetError::Invalid("invalid reply SHA-256".into()));
    }
    Ok(())
}

fn event_invocation(event: &BudgetEvent) -> &str {
    match event {
        BudgetEvent::Reserve { invocation_id, .. }
        | BudgetEvent::Settle { invocation_id, .. }
        | BudgetEvent::CostUnknown { invocation_id, .. }
        | BudgetEvent::AbortBeforeDispatch { invocation_id, .. } => invocation_id,
    }
}

fn require_active(entries: &[JournalEntry], invocation_id: &str) -> Result<(), BudgetError> {
    let mut active = false;
    for entry in entries {
        match &entry.event {
            BudgetEvent::Reserve {
                invocation_id: id, ..
            } if id == invocation_id => active = true,
            BudgetEvent::Settle {
                invocation_id: id, ..
            } if id == invocation_id => active = false,
            _ => {}
        }
    }
    if active {
        Ok(())
    } else {
        Err(BudgetError::UnknownInvocation(invocation_id.into()))
    }
}

fn summarize(entries: &[JournalEntry], cap: u64) -> Result<BudgetSnapshot, BudgetError> {
    let mut active = BTreeMap::<String, u64>::new();
    let mut seen = BTreeSet::<String>::new();
    let mut settled = 0u64;
    let mut blocked = false;
    for entry in entries {
        match &entry.event {
            BudgetEvent::Reserve {
                invocation_id,
                reserved_usd_micros,
                ..
            } => {
                if !seen.insert(invocation_id.clone()) {
                    return Err(BudgetError::Invalid(format!(
                        "duplicate invocation {invocation_id}"
                    )));
                }
                active.insert(invocation_id.clone(), *reserved_usd_micros);
            }
            BudgetEvent::Settle {
                invocation_id,
                settled_usd_micros,
                ..
            } => {
                let reserved_usd_micros = active.remove(invocation_id).ok_or_else(|| {
                    BudgetError::Invalid(format!(
                        "settlement without active reservation {invocation_id}"
                    ))
                })?;
                if *settled_usd_micros > reserved_usd_micros {
                    // Preserve the charged amount in the journal, but fail closed: the provider
                    // exceeded the liability admitted before dispatch.
                    blocked = true;
                }
                settled = settled
                    .checked_add(*settled_usd_micros)
                    .ok_or_else(|| BudgetError::Invalid("settled cost overflow".into()))?;
            }
            BudgetEvent::CostUnknown { invocation_id, .. } => {
                if !active.contains_key(invocation_id) {
                    return Err(BudgetError::Invalid(format!(
                        "unknown cost without active reservation {invocation_id}"
                    )));
                }
                blocked = true;
            }
            BudgetEvent::AbortBeforeDispatch { invocation_id, .. } => {
                if active.remove(invocation_id).is_none() {
                    return Err(BudgetError::Invalid(format!(
                        "abort without active reservation {invocation_id}"
                    )));
                }
            }
        }
    }
    let active_reserved = active.values().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| BudgetError::Invalid("reservation overflow".into()))
    })?;
    let liability = settled
        .checked_add(active_reserved)
        .ok_or_else(|| BudgetError::Invalid("liability overflow".into()))?;
    Ok(BudgetSnapshot {
        cap_usd_micros: cap,
        settled_usd_micros: settled,
        active_reserved_usd_micros: active_reserved,
        remaining_usd_micros: cap.saturating_sub(liability),
        blocked: blocked || liability > cap,
        entries: entries.len() as u64,
    })
}

fn read_and_verify(path: &Path) -> Result<Vec<JournalEntry>, BudgetError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let mut entries = Vec::new();
    let mut expected_prev = "0".repeat(64);
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            return Err(BudgetError::Invalid(format!("empty line {}", index + 1)));
        }
        let entry: JournalEntry = serde_json::from_str(&line)
            .map_err(|e| BudgetError::Invalid(format!("line {}: {e}", index + 1)))?;
        if entry.schema != BUDGET_SCHEMA
            || entry.seq != index as u64 + 1
            || entry.prev_sha256 != expected_prev
        {
            return Err(BudgetError::Invalid(format!(
                "line {} sequence, schema, or predecessor mismatch",
                index + 1
            )));
        }
        let actual = hash_material(&entry)?;
        if actual != entry.entry_sha256 {
            return Err(BudgetError::Invalid(format!(
                "line {} digest mismatch",
                index + 1
            )));
        }
        expected_prev = entry.entry_sha256.clone();
        entries.push(entry);
    }
    Ok(entries)
}

fn hash_material(entry: &JournalEntry) -> Result<String, BudgetError> {
    let bytes = serde_json::to_vec(&EntryMaterial {
        schema: &entry.schema,
        seq: entry.seq,
        at_unix_ms: entry.at_unix_ms,
        prev_sha256: &entry.prev_sha256,
        event: &entry.event,
    })
    .map_err(|e| BudgetError::Invalid(e.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn append(path: &Path, prior: &[JournalEntry], event: BudgetEvent) -> Result<(), BudgetError> {
    let seq = prior.len() as u64 + 1;
    let prev_sha256 = prior
        .last()
        .map(|e| e.entry_sha256.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| BudgetError::Invalid(e.to_string()))?
        .as_millis();
    let mut entry = JournalEntry {
        schema: BUDGET_SCHEMA.into(),
        seq,
        at_unix_ms,
        prev_sha256,
        event,
        entry_sha256: String::new(),
    };
    entry.entry_sha256 = hash_material(&entry)?;
    let mut bytes = serde_json::to_vec(&entry).map_err(|e| BudgetError::Invalid(e.to_string()))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Parses a non-negative decimal USD amount and rounds upward to the nearest micro-dollar.
pub fn parse_usd_to_micro_ceil(input: &str) -> Result<u64, BudgetError> {
    let input = input.trim();
    if input.is_empty() || input.starts_with('-') {
        return Err(BudgetError::Money("amount must be non-negative".into()));
    }
    let input = input.strip_prefix('+').unwrap_or(input);
    let (mantissa, exponent) = match input.find(['e', 'E']) {
        Some(i) => {
            let exp = input[i + 1..]
                .parse::<i32>()
                .map_err(|_| BudgetError::Money("invalid exponent".into()))?;
            (&input[..i], exp)
        }
        None => (input, 0),
    };
    let mut digits = String::new();
    let mut fractional = 0i32;
    let mut seen_dot = false;
    for b in mantissa.bytes() {
        match b {
            b'0'..=b'9' => {
                digits.push(b as char);
                if seen_dot {
                    fractional += 1;
                }
            }
            b'.' if !seen_dot => seen_dot = true,
            _ => return Err(BudgetError::Money("invalid decimal".into())),
        }
    }
    if digits.is_empty() {
        return Err(BudgetError::Money("invalid decimal".into()));
    }
    let value = digits
        .parse::<u128>()
        .map_err(|_| BudgetError::Money("amount overflow".into()))?;
    let scale = exponent + 6 - fractional;
    let micros = if scale >= 0 {
        value
            .checked_mul(pow10(scale as u32)?)
            .ok_or_else(|| BudgetError::Money("amount overflow".into()))?
    } else {
        let divisor = pow10((-scale) as u32)?;
        let quotient = value / divisor;
        if value % divisor == 0 {
            quotient
        } else {
            quotient + 1
        }
    };
    u64::try_from(micros).map_err(|_| BudgetError::Money("amount overflow".into()))
}

fn pow10(power: u32) -> Result<u128, BudgetError> {
    10u128
        .checked_pow(power)
        .ok_or_else(|| BudgetError::Money("decimal scale overflow".into()))
}

pub fn derived_token_cost_micro(
    tokens: u64,
    usd_micros_per_million_tokens: u64,
) -> Result<u64, BudgetError> {
    let numerator = u128::from(tokens)
        .checked_mul(u128::from(usd_micros_per_million_tokens))
        .ok_or_else(|| BudgetError::Money("token cost overflow".into()))?;
    let cost = (numerator + 999_999) / 1_000_000;
    u64::try_from(cost).map_err(|_| BudgetError::Money("token cost overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "loop-cycle-budget-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn decimal_money_rounds_up_without_float() {
        assert_eq!(parse_usd_to_micro_ceil("1.25").unwrap(), 1_250_000);
        assert_eq!(parse_usd_to_micro_ceil("0.0000001").unwrap(), 1);
        assert_eq!(parse_usd_to_micro_ceil("1.23e-3").unwrap(), 1_230);
        assert!(parse_usd_to_micro_ceil("-1").is_err());
    }

    #[test]
    fn token_cost_rounds_up() {
        assert_eq!(derived_token_cost_micro(1, 2_000_000).unwrap(), 2);
        assert_eq!(
            derived_token_cost_micro(1_000_000, 10_000_000).unwrap(),
            10_000_000
        );
    }

    #[test]
    fn reserve_settle_and_cap_are_fail_closed() {
        let root = root("cap");
        let journal = BudgetJournal::new(&root, 20_000_000).unwrap();
        let first = journal
            .reserve(
                "i-1",
                "design",
                "openrouter",
                "google/gemini-4-argon",
                12_000_000,
            )
            .unwrap();
        assert_eq!(first.remaining_usd_micros, 8_000_000);
        assert!(matches!(
            journal.reserve(
                "i-2",
                "review",
                "openrouter",
                "google/gemini-4-argon",
                8_000_001
            ),
            Err(BudgetError::CapExceeded { .. })
        ));
        let settled = journal
            .settle(
                "i-1",
                1_500_000,
                CostAuthority::Measured,
                "gen-1",
                &"a".repeat(64),
            )
            .unwrap();
        assert_eq!(settled.settled_usd_micros, 1_500_000);
        assert_eq!(settled.active_reserved_usd_micros, 0);
        assert_eq!(settled.entries, 2);
    }

    #[test]
    fn unknown_cost_keeps_reservation_and_blocks_dispatch() {
        let root = root("unknown");
        let journal = BudgetJournal::new(&root, 25_000_000).unwrap();
        journal
            .reserve(
                "i-1",
                "review",
                "anthropic",
                "anthropic/claude-sonnet-5-5",
                5_000_000,
            )
            .unwrap();
        journal.cost_unknown("i-1", "usage missing").unwrap();
        let snapshot = journal.snapshot().unwrap();
        assert!(snapshot.blocked);
        assert_eq!(snapshot.active_reserved_usd_micros, 5_000_000);
        assert_eq!(
            journal.reserve(
                "i-2",
                "review",
                "anthropic",
                "anthropic/claude-sonnet-5-5",
                1
            ),
            Err(BudgetError::Blocked)
        );
    }

    #[test]
    fn settlement_over_reservation_is_recorded_and_blocks_dispatch() {
        let root = root("over-reservation");
        let journal = BudgetJournal::new(&root, 25_000_000).unwrap();
        journal
            .reserve(
                "i-1",
                "review",
                "anthropic",
                "anthropic/claude-sonnet-5-5",
                5_000_000,
            )
            .unwrap();
        let snapshot = journal
            .settle(
                "i-1",
                5_000_001,
                CostAuthority::Derived,
                "msg-1",
                &"b".repeat(64),
            )
            .unwrap();
        assert_eq!(snapshot.settled_usd_micros, 5_000_001);
        assert_eq!(snapshot.active_reserved_usd_micros, 0);
        assert!(snapshot.blocked);
        assert_eq!(
            journal.reserve(
                "i-2",
                "review",
                "anthropic",
                "anthropic/claude-sonnet-5-5",
                1,
            ),
            Err(BudgetError::Blocked)
        );
    }

    #[test]
    fn tampering_is_detected() {
        let root = root("tamper");
        let journal = BudgetJournal::new(&root, 1_000_000).unwrap();
        journal
            .reserve("i-1", "design", "openrouter", "google/gemini-4-argon", 1)
            .unwrap();
        let path = root.join("events.jsonl");
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("\"reserved_usd_micros\":1", "\"reserved_usd_micros\":2");
        fs::write(path, text).unwrap();
        assert!(matches!(journal.snapshot(), Err(BudgetError::Invalid(_))));
    }
}

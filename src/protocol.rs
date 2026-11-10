//! Additive, versioned read model for detachable clients.
//!
//! This module intentionally does not own transitions, launch processes, or persist state. The
//! existing state machine and append-only event chain remain authoritative.

use std::path::Path;

use serde_json::{json, Value};

use crate::budget::BudgetJournal;
use crate::cycle;

pub const PROTOCOL_VERSION: u32 = 1;

pub fn capabilities() -> Value {
    json!({
        "schema": "loop-cycle-capabilities/1",
        "protocol_version": PROTOCOL_VERSION,
        "harness": {
            "name": "loop-cycle",
            "version": env!("CARGO_PKG_VERSION")
        },
        "run_modes": ["full", "planning"],
        "commands": {
            "run": true,
            "preflight_json": true,
            "status_json": true,
            "cancel_cycle": true,
            "resume": true,
            "reconcile": true
        },
        "scheduler_lanes": ["agy", "claude", "codex"],
        "ui_contract": {
            "detachable": true,
            "state_authority": "harness",
            "unknown_fields": "ignore"
        },
        "telemetry": {
            "invocation_counts": "measured",
            "spend_enforcement": "hash_chained_reservation_journal_candidate",
            "paid_start": "requires_profile_preflight_and_epoch1_promotion",
            "unknown_cost_policy": "fail_closed"
        }
    })
}

pub fn status_envelope(dir: &Path) -> (Value, bool) {
    let events_path = dir.join("events.jsonl");
    let chain = cycle::verify_events(&events_path);
    let state_text = std::fs::read_to_string(dir.join("state.json"));

    let mut errors = Vec::new();
    let (events, verified_event_values) = match chain {
        Ok(n) => match read_event_values(&events_path) {
            Ok(values) => (Some(n), Some(values)),
            Err(e) => {
                errors.push(format!("events.jsonl: {e}"));
                (None, None)
            }
        },
        Err(e) => {
            errors.push(format!("events.jsonl: {e}"));
            (None, None)
        }
    };
    let state: Option<Value> = match state_text {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(value) => Some(value),
            Err(e) => {
                errors.push(format!("state.json: malformed JSON: {e}"));
                None
            }
        },
        Err(e) => {
            errors.push(format!("state.json: {e}"));
            None
        }
    };

    let projection = state.as_ref().map(|s| {
        json!({
            "cycle_id": s.get("cycle_id").cloned().unwrap_or(Value::Null),
            "state": s.get("state").cloned().unwrap_or(Value::Null),
            "next": s.get("next").cloned().unwrap_or(Value::Null),
            "used": s.get("used").cloned().unwrap_or(Value::Null),
            "design_rev": s.get("design_rev").cloned().unwrap_or(Value::Null),
            "brief_rounds_used": s.get("brief_rounds_used").cloned().unwrap_or(Value::Null),
            "impl_rounds_used": s.get("impl_rounds_used").cloned().unwrap_or(Value::Null),
            "swarm_used": s.get("swarm_used").cloned().unwrap_or(Value::Null),
            "reserve_held": s.get("reserve_held").cloned().unwrap_or(Value::Null),
            "elapsed_secs": s.get("elapsed_secs").cloned().unwrap_or(Value::Null)
        })
    });
    let provider_receipts: Vec<Value> = verified_event_values
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|event| event.pointer("/data/provider_receipt").cloned())
        .collect();
    let model_verdicts: Vec<Value> = verified_event_values
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|event| event.get("kind").and_then(Value::as_str) == Some("review"))
        .map(|event| {
            json!({
                "at_utc": event.get("at_utc").cloned().unwrap_or(Value::Null),
                "data": event.get("data").cloned().unwrap_or(Value::Null),
                "files": event.get("files").cloned().unwrap_or_else(|| json!([]))
            })
        })
        .collect();
    let (profile, spend) = match verified_event_values.as_deref() {
        Some(values) => match spend_projection(dir, values) {
            Ok(result) => result,
            Err(e) => {
                errors.push(format!("spend telemetry: {e}"));
                (Value::Null, Value::Null)
            }
        },
        None => (Value::Null, Value::Null),
    };
    let ok = errors.is_empty();
    (
        json!({
            "schema": "loop-cycle-status/1",
            "protocol_version": PROTOCOL_VERSION,
            "ok": ok,
            "chain": {
                "valid": events.is_some(),
                "events": events
            },
            "cycle": projection,
            "profile": profile,
            "spend": spend,
            "provider_receipts": provider_receipts,
            "model_verdicts": model_verdicts,
            "errors": errors
        }),
        ok,
    )
}

fn read_event_values(path: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|e| format!("line {}: {e}", index + 1))
        })
        .collect()
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn spend_projection(dir: &Path, events: &[Value]) -> Result<(Value, Value), String> {
    let profile = events
        .iter()
        .find(|event| event.get("kind").and_then(Value::as_str) == Some("start"))
        .and_then(|event| event.pointer("/data/profile"))
        .cloned()
        .unwrap_or(Value::Null);
    if profile.is_null() {
        return Ok((
            Value::Null,
            json!({"schema":"loop-cycle-spend/1", "providers":[]}),
        ));
    }
    let budgets = profile
        .get("budgets")
        .and_then(Value::as_array)
        .ok_or_else(|| "start profile has no budgets array".to_string())?;
    let mut providers = Vec::new();
    let mut total_cap = 0u64;
    let mut total_settled = 0u64;
    let mut total_reserved = 0u64;
    let mut any_blocked = false;
    for budget in budgets {
        let provider_id = budget
            .get("provider_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "profile budget has no provider_id".to_string())?;
        if !safe_segment(provider_id) {
            return Err(format!("unsafe provider ID {provider_id:?}"));
        }
        let cap = budget
            .get("cap_usd_micros")
            .and_then(Value::as_u64)
            .filter(|cap| *cap > 0)
            .ok_or_else(|| format!("provider {provider_id} has no positive cap"))?;
        let classification = budget
            .get("settlement")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("provider {provider_id} has no settlement classification"))?;
        let snapshot = BudgetJournal::new(dir.join("stages").join("budget").join(provider_id), cap)
            .map_err(|e| format!("provider {provider_id}: {e:?}"))?
            .snapshot()
            .map_err(|e| format!("provider {provider_id}: {e:?}"))?;
        total_cap = total_cap
            .checked_add(snapshot.cap_usd_micros)
            .ok_or_else(|| "total cap overflow".to_string())?;
        total_settled = total_settled
            .checked_add(snapshot.settled_usd_micros)
            .ok_or_else(|| "total settled spend overflow".to_string())?;
        total_reserved = total_reserved
            .checked_add(snapshot.active_reserved_usd_micros)
            .ok_or_else(|| "total reservation overflow".to_string())?;
        any_blocked |= snapshot.blocked;
        providers.push(json!({
            "provider_id": provider_id,
            "classification": classification,
            "cap_usd_micros": snapshot.cap_usd_micros,
            "settled_usd_micros": snapshot.settled_usd_micros,
            "active_reserved_usd_micros": snapshot.active_reserved_usd_micros,
            "remaining_usd_micros": snapshot.remaining_usd_micros,
            "blocked": snapshot.blocked,
            "journal_entries": snapshot.entries
        }));
    }
    Ok((
        profile,
        json!({
            "schema": "loop-cycle-spend/1",
            "providers": providers,
            "total_cap_usd_micros": total_cap,
            "total_settled_usd_micros": total_settled,
            "total_active_reserved_usd_micros": total_reserved,
            "blocked": any_blocked
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::CostAuthority;

    fn cycle_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "loop-cycle-status-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("stages")).unwrap();
        root
    }

    fn write_profile_cycle(root: &Path) {
        let event = json!({
            "seq": 1,
            "at_utc": "2026-11-02T00:00:00.000Z",
            "kind": "start",
            "prev_sha256": cycle::sha256_hex(b""),
            "data": {
                "profile": {
                    "schema": "loop-cycle-execution-profile/1",
                    "id": "fixture",
                    "sha256": "a".repeat(64),
                    "budgets": [{
                        "provider_id": "openrouter",
                        "cap_usd_micros": 20_000_000,
                        "settlement": "measured"
                    }],
                    "roles": []
                }
            },
            "files": []
        });
        std::fs::write(
            root.join("events.jsonl"),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            root.join("state.json"),
            serde_json::to_vec(&json!({
                "cycle_id": "fixture",
                "state": "Done(PlanningComplete)",
                "used": {"agy":1,"claude":1,"codex":0}
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn status_projects_verified_budget_journal() {
        let root = cycle_root("spend");
        write_profile_cycle(&root);
        let journal = BudgetJournal::new(
            root.join("stages").join("budget").join("openrouter"),
            20_000_000,
        )
        .unwrap();
        journal
            .reserve(
                "inv-001",
                "design_author",
                "openrouter",
                "google/gemini-4-argon",
                20_000_000,
            )
            .unwrap();
        journal
            .settle(
                "inv-001",
                1_250_000,
                CostAuthority::Measured,
                "gen-1",
                &"b".repeat(64),
            )
            .unwrap();

        let (status, ok) = status_envelope(&root);
        assert!(ok, "{status}");
        assert_eq!(
            status.pointer("/spend/providers/0/settled_usd_micros"),
            Some(&json!(1_250_000))
        );
        assert_eq!(
            status.pointer("/spend/providers/0/classification"),
            Some(&json!("measured"))
        );
        assert_eq!(status.pointer("/spend/blocked"), Some(&json!(false)));
    }

    #[test]
    fn status_fails_closed_on_tampered_budget_journal() {
        let root = cycle_root("tamper");
        write_profile_cycle(&root);
        let journal_root = root.join("stages").join("budget").join("openrouter");
        let journal = BudgetJournal::new(&journal_root, 20_000_000).unwrap();
        journal
            .reserve(
                "inv-001",
                "design_author",
                "openrouter",
                "google/gemini-4-argon",
                1,
            )
            .unwrap();
        let path = journal_root.join("events.jsonl");
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"reserved_usd_micros\":1", "\"reserved_usd_micros\":2");
        std::fs::write(path, text).unwrap();

        let (status, ok) = status_envelope(&root);
        assert!(!ok);
        assert!(status["errors"][0]
            .as_str()
            .is_some_and(|error| error.contains("spend telemetry")));
    }
}

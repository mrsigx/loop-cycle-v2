//! Provider-neutral run contracts and sanitized receipts for paid planning adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::{derived_token_cost_micro, BudgetError};
use crate::Agent;

pub const RUN_CONTRACT_SCHEMA: &str = "loop-cycle-provider-run/1";
pub const RECEIPT_SCHEMA: &str = "loop-cycle-provider-receipt/1";
pub const PROFILE_SCHEMA: &str = "loop-cycle-execution-profile/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfile {
    pub schema: String,
    pub id: String,
    pub run_mode: String,
    pub telemetry_required: bool,
    pub budgets: Vec<ProfileBudget>,
    pub roles: Vec<ProfileRole>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBudget {
    pub provider_id: String,
    pub cap_usd_micros: u64,
    pub settlement: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRole {
    pub role_id: String,
    pub scheduler_lane: Agent,
    pub adapter_id: String,
    pub provider_id: String,
    pub requested_model: String,
    pub normalized_model: String,
    pub wrapper_path: PathBuf,
    pub wrapper_sha256: String,
    pub price_manifest_path: Option<PathBuf>,
    pub price_manifest_sha256: Option<String>,
    pub receipt_required: bool,
}

fn safe_profile_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn profile_preflight(path: &Path, expected_sha256: &str) -> serde_json::Value {
    let mut checks = Vec::new();
    let mut errors = Vec::new();
    let mut profile_view = serde_json::Value::Null;
    let expected = expected_sha256.to_ascii_lowercase();
    if let Err(e) = validate_sha256(&expected) {
        errors.push(e);
    }
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) => {
            errors.push(format!("profile read failed: {e}"));
            Vec::new()
        }
    };
    let actual = format!("{:x}", Sha256::digest(&raw));
    let digest_ok = !raw.is_empty() && actual == expected;
    checks.push(serde_json::json!({"id":"profile_digest", "ok":digest_ok, "actual":actual}));
    if !digest_ok {
        errors.push("profile digest mismatch".into());
    }
    let profile: Option<ExecutionProfile> = match serde_json::from_slice(&raw) {
        Ok(profile) => Some(profile),
        Err(e) => {
            errors.push(format!("profile parse failed: {e}"));
            None
        }
    };
    if let Some(profile) = profile {
        profile_view = serde_json::json!({
            "id": &profile.id,
            "run_mode": &profile.run_mode,
            "budgets": &profile.budgets,
            "roles": &profile.roles
        });
        let shape_ok = profile.schema == PROFILE_SCHEMA
            && profile.run_mode == "planning"
            && profile.telemetry_required
            && !profile.roles.is_empty()
            && !profile.budgets.is_empty();
        checks.push(serde_json::json!({"id":"profile_shape", "ok":shape_ok}));
        if !shape_ok {
            errors.push("profile is not a telemetry-required planning profile".into());
        }
        let mut role_ids = BTreeSet::new();
        let mut providers = BTreeMap::new();
        for budget in &profile.budgets {
            if !safe_profile_segment(&budget.provider_id) {
                errors.push(format!("unsafe provider ID {:?}", budget.provider_id));
            }
            if providers
                .insert(
                    budget.provider_id.clone(),
                    (budget.cap_usd_micros, budget.settlement.as_str()),
                )
                .is_some()
            {
                errors.push(format!("duplicate provider budget {}", budget.provider_id));
            }
        }
        for role in &profile.roles {
            if !safe_profile_segment(&role.role_id)
                || !safe_profile_segment(&role.provider_id)
                || !safe_profile_segment(&role.adapter_id)
            {
                errors.push(format!(
                    "role {} contains an unsafe identifier",
                    role.role_id
                ));
            }
            if !role_ids.insert(role.role_id.clone()) {
                errors.push(format!("duplicate role {}", role.role_id));
            }
            let budget_ok = providers.contains_key(&role.provider_id);
            let wrapper_ok =
                verify_profile_file_digest(path, &role.wrapper_path, &role.wrapper_sha256);
            let price_ok = match (&role.price_manifest_path, &role.price_manifest_sha256) {
                (None, None) => true,
                (Some(artifact), Some(digest)) => {
                    verify_profile_file_digest(path, artifact, digest)
                }
                _ => false,
            };
            checks.push(serde_json::json!({
                "id": format!("role:{}", role.role_id),
                "ok": budget_ok && wrapper_ok && price_ok && role.receipt_required,
                "provider_id": role.provider_id,
                "adapter_id": role.adapter_id,
                "requested_model": role.requested_model,
                "normalized_model": role.normalized_model,
                "wrapper_ok": wrapper_ok,
                "price_manifest_ok": price_ok,
                "receipt_required": role.receipt_required
            }));
            if !(budget_ok && wrapper_ok && price_ok && role.receipt_required) {
                errors.push(format!("role {} failed binding checks", role.role_id));
            }
        }
        let caps_ok = providers.get("openrouter") == Some(&(20_000_000, "measured"))
            && providers.get("anthropic") == Some(&(25_000_000, "derived"))
            && providers.len() == 2;
        checks.push(serde_json::json!({"id":"operator_caps", "ok":caps_ok}));
        if !caps_ok {
            errors.push(
                "profile must bind exactly $20 measured OpenRouter and $25 derived Anthropic"
                    .into(),
            );
        }
        if profile.id == "sonnet55-argon4-planning-v1" {
            let exact_role = |id: &str,
                              lane: Agent,
                              adapter: &str,
                              provider: &str,
                              requested: &str,
                              normalized: &str,
                              price_required: bool| {
                profile
                    .roles
                    .iter()
                    .filter(|role| role.role_id == id)
                    .collect::<Vec<_>>()
                    .as_slice()
                    .first()
                    .is_some_and(|role| {
                        profile.roles.iter().filter(|r| r.role_id == id).count() == 1
                            && role.scheduler_lane == lane
                            && role.adapter_id == adapter
                            && role.provider_id == provider
                            && role.requested_model == requested
                            && role.normalized_model == normalized
                            && role.receipt_required
                            && (price_required
                                == (role.price_manifest_path.is_some()
                                    && role.price_manifest_sha256.is_some()))
                    })
            };
            let bindings_ok = exact_role(
                "design_author",
                Agent::Agy,
                "openrouter-argon-v1",
                "openrouter",
                "google/gemini-4-argon",
                "google/gemini-4-argon",
                false,
            ) && exact_role(
                "design_review",
                Agent::Claude,
                "anthropic-sonnet55-v1",
                "anthropic",
                "claude-sonnet-5-5",
                "anthropic/claude-sonnet-5-5",
                true,
            ) && exact_role(
                "feasibility_review",
                Agent::Codex,
                "openrouter-argon-v1",
                "openrouter",
                "google/gemini-4-argon",
                "google/gemini-4-argon",
                false,
            );
            checks.push(serde_json::json!({
                "id":"sonnet55_argon4_required_bindings",
                "ok":bindings_ok,
                "required_roles":["design_author","design_review","feasibility_review"]
            }));
            if !bindings_ok {
                errors.push(
                    "sonnet55-argon4-planning-v1 required role binding is missing or inconsistent"
                        .into(),
                );
            }
        }
    }
    serde_json::json!({
        "schema":"loop-cycle-preflight/1",
        "protocol_version":1,
        "ok":errors.is_empty(),
        "profile_path":path.to_string_lossy(),
        "profile_sha256":expected,
        "profile":profile_view,
        "checks":checks,
        "errors":errors
    })
}

pub fn load_execution_profile(
    path: &Path,
    expected_sha256: &str,
) -> Result<ExecutionProfile, String> {
    let report = profile_preflight(path, expected_sha256);
    if !report.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(format!(
            "profile preflight failed: {}",
            report
                .get("errors")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        ));
    }
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let mut profile: ExecutionProfile = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    for role in &mut profile.roles {
        role.wrapper_path = resolve_profile_artifact(path, &role.wrapper_path)?;
        if let Some(price) = &role.price_manifest_path {
            role.price_manifest_path = Some(resolve_profile_artifact(path, price)?);
        }
    }
    Ok(profile)
}

fn resolve_profile_artifact(profile_path: &Path, artifact: &Path) -> Result<PathBuf, String> {
    let joined = if artifact.is_absolute() {
        artifact.to_path_buf()
    } else {
        profile_path
            .parent()
            .ok_or_else(|| "profile path has no parent".to_string())?
            .join(artifact)
    };
    fs::canonicalize(&joined).map_err(|e| format!("resolve {}: {e}", joined.display()))
}

fn verify_profile_file_digest(profile_path: &Path, artifact: &Path, expected: &str) -> bool {
    if validate_sha256(expected).is_err() {
        return false;
    }
    resolve_profile_artifact(profile_path, artifact)
        .and_then(|path| fs::read(path).map_err(|e| e.to_string()))
        .map(|raw| format!("{:x}", Sha256::digest(raw)) == expected.to_ascii_lowercase())
        .unwrap_or(false)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunContract {
    pub schema: String,
    pub planning_only: bool,
    pub cycle_id: String,
    pub invocation_id: String,
    pub role_id: String,
    pub adapter_id: String,
    pub provider_id: String,
    pub requested_model: String,
    pub normalized_model: String,
    pub cap_usd_micros: u64,
    pub reservation_usd_micros: u64,
    pub profile_sha256: String,
    pub price_manifest_sha256: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VerifiedRunContract {
    pub contract: RunContract,
    pub raw_sha256: String,
}

impl VerifiedRunContract {
    pub fn budget_dir(&self, stage: &Path) -> Result<PathBuf, String> {
        let parent = stage
            .parent()
            .ok_or_else(|| "stage has no cycle parent".to_string())?;
        Ok(parent.join("budget").join(&self.contract.provider_id))
    }
}

pub fn load_run_contract(
    stage: &Path,
    adapter_id: &str,
    provider_id: &str,
    requested_model: &str,
    hard_cap_usd_micros: u64,
) -> Result<VerifiedRunContract, String> {
    let path = stage.join("run-contract.json");
    let digest_path = stage.join("run-contract.sha256");
    let raw = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let actual = format!("{:x}", Sha256::digest(&raw));
    let expected = fs::read_to_string(&digest_path)
        .map_err(|e| format!("read {}: {e}", digest_path.display()))?
        .trim()
        .to_ascii_lowercase();
    validate_sha256(&expected)?;
    if actual != expected {
        return Err(format!(
            "run contract digest mismatch: expected {expected}, actual {actual}"
        ));
    }
    let contract: RunContract =
        serde_json::from_slice(&raw).map_err(|e| format!("run contract: {e}"))?;
    if contract.schema != RUN_CONTRACT_SCHEMA
        || !contract.planning_only
        || contract.adapter_id != adapter_id
        || contract.provider_id != provider_id
        || contract.requested_model != requested_model
        || contract.cap_usd_micros != hard_cap_usd_micros
        || contract.reservation_usd_micros == 0
        || contract.reservation_usd_micros > hard_cap_usd_micros
    {
        return Err("run contract does not match this planning adapter and hard cap".into());
    }
    for (name, value) in [
        ("cycle_id", contract.cycle_id.as_str()),
        ("invocation_id", contract.invocation_id.as_str()),
        ("role_id", contract.role_id.as_str()),
        ("normalized_model", contract.normalized_model.as_str()),
    ] {
        validate_id(name, value)?;
    }
    validate_sha256(&contract.profile_sha256)?;
    if let Some(digest) = &contract.price_manifest_sha256 {
        validate_sha256(digest)?;
    }
    Ok(VerifiedRunContract {
        contract,
        raw_sha256: actual,
    })
}

fn validate_id(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':'))
    {
        return Err(format!("invalid {name}"));
    }
    Ok(())
}

pub fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid SHA-256".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReceipt {
    pub schema: String,
    pub run_contract_sha256: String,
    pub invocation_id: String,
    pub role_id: String,
    pub adapter_id: String,
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_provider: Option<String>,
    pub request_id: String,
    pub requested_model: String,
    pub resolved_model: String,
    pub raw_usage: serde_json::Value,
    pub cost_authority: String,
    pub cost_usd_micros: u64,
    pub raw_cost_usd: Option<String>,
    pub reply_sha256: String,
    pub finish_reason: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReceiptEvidence {
    pub schema: &'static str,
    pub invocation_id: String,
    pub role_id: String,
    pub adapter_id: String,
    pub provider_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_provider: Option<String>,
    pub request_id: String,
    pub requested_model: String,
    pub resolved_model: String,
    pub cost_authority: String,
    pub cost_usd_micros: u64,
    pub reply_sha256: String,
    pub receipt_sha256: String,
}

pub fn write_receipt(stage: &Path, receipt: &ProviderReceipt) -> Result<(), String> {
    if receipt.schema != RECEIPT_SCHEMA {
        return Err("invalid provider receipt schema".into());
    }
    validate_sha256(&receipt.run_contract_sha256)?;
    validate_sha256(&receipt.reply_sha256)?;
    let path = stage.join("provider-receipt.json");
    let bytes = serde_json::to_vec_pretty(receipt).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(())
}

/// Validates the immutable identity and accounting portion of a receipt. This is also used to pin
/// charged failures, where the adapter intentionally withholds the rejected model output.
pub fn validate_provider_receipt_evidence(
    stage: &Path,
    verified: &VerifiedRunContract,
    expected_profile_sha256: &str,
    role: &ProfileRole,
    budget: &ProfileBudget,
    invocation_id: &str,
) -> Result<ReceiptEvidence, String> {
    if verified.contract.profile_sha256 != expected_profile_sha256.to_ascii_lowercase()
        || verified.contract.invocation_id != invocation_id
        || verified.contract.role_id != role.role_id
        || verified.contract.adapter_id != role.adapter_id
        || verified.contract.provider_id != role.provider_id
        || verified.contract.requested_model != role.requested_model
        || verified.contract.normalized_model != role.normalized_model
        || verified.contract.cap_usd_micros != budget.cap_usd_micros
    {
        return Err("run contract does not match the active profile binding".into());
    }

    let path = stage.join("provider-receipt.json");
    let raw = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if raw.len() > 1024 * 1024 {
        return Err("provider receipt exceeds 1 MiB".into());
    }
    let receipt: ProviderReceipt =
        serde_json::from_slice(&raw).map_err(|e| format!("provider receipt: {e}"))?;
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.run_contract_sha256 != verified.raw_sha256
        || receipt.invocation_id != invocation_id
        || receipt.role_id != role.role_id
        || receipt.adapter_id != role.adapter_id
        || receipt.provider_id != role.provider_id
        || receipt.requested_model != role.requested_model
        || receipt.cost_authority != budget.settlement
    {
        return Err("provider receipt identity or cost authority mismatch".into());
    }
    if receipt.request_id.is_empty()
        || receipt.request_id.len() > 512
        || receipt.request_id.chars().any(char::is_control)
        || receipt.routing_provider.as_ref().is_some_and(|provider| {
            provider.is_empty() || provider.len() > 160 || provider.chars().any(char::is_control)
        })
        || !receipt.raw_usage.is_object()
    {
        return Err("provider receipt has an invalid request ID or usage object".into());
    }
    validate_sha256(&receipt.reply_sha256)?;
    Ok(ReceiptEvidence {
        schema: "loop-cycle-provider-receipt-evidence/1",
        invocation_id: receipt.invocation_id,
        role_id: receipt.role_id,
        adapter_id: receipt.adapter_id,
        provider_id: receipt.provider_id,
        routing_provider: receipt.routing_provider,
        request_id: receipt.request_id,
        requested_model: receipt.requested_model,
        resolved_model: receipt.resolved_model,
        cost_authority: receipt.cost_authority,
        cost_usd_micros: receipt.cost_usd_micros,
        reply_sha256: receipt.reply_sha256,
        receipt_sha256: format!("{:x}", Sha256::digest(raw)),
    })
}

/// Reads and validates the paid-adapter receipt before the conductor admits stdout as a reply.
/// The paid adapters emit the model text without adding bytes, so the receipt digest binds stdout
/// exactly, including any line ending that was already part of the model text.
pub fn validate_provider_receipt(
    stage: &Path,
    verified: &VerifiedRunContract,
    expected_profile_sha256: &str,
    role: &ProfileRole,
    budget: &ProfileBudget,
    invocation_id: &str,
    captured_stdout: &[u8],
) -> Result<ReceiptEvidence, String> {
    let evidence = validate_provider_receipt_evidence(
        stage,
        verified,
        expected_profile_sha256,
        role,
        budget,
        invocation_id,
    )?;
    if evidence.resolved_model != role.requested_model {
        return Err(format!(
            "resolved model {:?} does not match requested {:?}",
            evidence.resolved_model, role.requested_model
        ));
    }
    let actual_reply = format!("{:x}", Sha256::digest(captured_stdout));
    if actual_reply != evidence.reply_sha256 {
        return Err(format!(
            "provider receipt reply digest mismatch: expected {}, actual {actual_reply}",
            evidence.reply_sha256
        ));
    }
    Ok(evidence)
}

fn usage_u64(usage: &serde_json::Value, key: &str) -> Result<u64, String> {
    usage
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("missing or invalid usage.{key}"))
}

/// Strict candidate pricing for Sonnet 5.5. A future admitted price manifest replaces these
/// constants; until then, callers must keep paid Start disabled outside an offline fixture.
pub fn sonnet55_candidate_cost_usd_micros(usage: &serde_json::Value) -> Result<u64, String> {
    let input = usage_u64(usage, "input_tokens")?;
    let output = usage_u64(usage, "output_tokens")?;
    let cache_read = usage
        .get("cache_read_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cache_total = usage
        .get("cache_creation_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cache = usage.get("cache_creation");
    let cache_5m = cache
        .and_then(|v| v.get("ephemeral_5m_input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cache_1h = cache
        .and_then(|v| v.get("ephemeral_1h_input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if cache_total != cache_5m.saturating_add(cache_1h) {
        return Err("cache creation total lacks complete TTL breakdown".into());
    }
    if let Some(tools) = usage.get("server_tool_use") {
        if tools
            .as_object()
            .map(|m| m.values().any(|v| v.as_u64().unwrap_or(0) != 0))
            .unwrap_or(true)
        {
            return Err("server-tool billing is not priced by the candidate manifest".into());
        }
    }
    let components = [
        derived_token_cost_micro(input, 2_000_000),
        derived_token_cost_micro(output, 10_000_000),
        derived_token_cost_micro(cache_read, 100_000),
        derived_token_cost_micro(cache_5m, 2_500_000),
        derived_token_cost_micro(cache_1h, 4_000_000),
    ];
    components.into_iter().try_fold(0u64, |sum, item| {
        let value = item.map_err(|e| match e {
            BudgetError::Money(s) => s,
            other => format!("{other:?}"),
        })?;
        sum.checked_add(value)
            .ok_or_else(|| "derived cost overflow".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt_fixture(name: &str) -> (PathBuf, VerifiedRunContract, ProfileRole, ProfileBudget) {
        let root = std::env::temp_dir().join(format!(
            "loop-cycle-receipt-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let role = ProfileRole {
            role_id: "design_author".into(),
            scheduler_lane: Agent::Agy,
            adapter_id: "openrouter-argon-v1".into(),
            provider_id: "openrouter".into(),
            requested_model: "google/gemini-4-argon".into(),
            normalized_model: "google/gemini-4-argon".into(),
            wrapper_path: root.join("wrapper.exe"),
            wrapper_sha256: "a".repeat(64),
            price_manifest_path: None,
            price_manifest_sha256: None,
            receipt_required: true,
        };
        let budget = ProfileBudget {
            provider_id: "openrouter".into(),
            cap_usd_micros: 20_000_000,
            settlement: "measured".into(),
        };
        let verified = VerifiedRunContract {
            contract: RunContract {
                schema: RUN_CONTRACT_SCHEMA.into(),
                planning_only: true,
                cycle_id: "cycle-a".into(),
                invocation_id: "inv-001".into(),
                role_id: role.role_id.clone(),
                adapter_id: role.adapter_id.clone(),
                provider_id: role.provider_id.clone(),
                requested_model: role.requested_model.clone(),
                normalized_model: role.normalized_model.clone(),
                cap_usd_micros: budget.cap_usd_micros,
                reservation_usd_micros: budget.cap_usd_micros,
                profile_sha256: "b".repeat(64),
                price_manifest_sha256: None,
            },
            raw_sha256: "c".repeat(64),
        };
        (root, verified, role, budget)
    }

    #[test]
    fn sonnet_cost_requires_cache_ttl_breakdown() {
        let usage = serde_json::json!({
            "input_tokens": 10,
            "output_tokens": 10,
            "cache_creation_input_tokens": 5,
            "cache_read_input_tokens": 0
        });
        assert!(sonnet55_candidate_cost_usd_micros(&usage).is_err());
    }

    #[test]
    fn sonnet_cost_is_integer_and_complete() {
        let usage = serde_json::json!({
            "input_tokens": 1_000_000,
            "output_tokens": 1_000_000,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0
        });
        assert_eq!(
            sonnet55_candidate_cost_usd_micros(&usage).unwrap(),
            12_000_000
        );
    }

    #[test]
    fn receipt_must_bind_contract_profile_and_reply_bytes() {
        let (root, verified, role, budget) = receipt_fixture("valid");
        let receipt = ProviderReceipt {
            schema: RECEIPT_SCHEMA.into(),
            run_contract_sha256: verified.raw_sha256.clone(),
            invocation_id: "inv-001".into(),
            role_id: role.role_id.clone(),
            adapter_id: role.adapter_id.clone(),
            provider_id: role.provider_id.clone(),
            routing_provider: None,
            request_id: "gen-1".into(),
            requested_model: role.requested_model.clone(),
            resolved_model: role.requested_model.clone(),
            raw_usage: serde_json::json!({"cost": 0.25}),
            cost_authority: "measured".into(),
            cost_usd_micros: 250_000,
            raw_cost_usd: Some("0.25".into()),
            reply_sha256: format!("{:x}", Sha256::digest(b"hello")),
            finish_reason: serde_json::json!("stop"),
        };
        write_receipt(&root, &receipt).unwrap();
        let evidence = validate_provider_receipt(
            &root,
            &verified,
            &verified.contract.profile_sha256,
            &role,
            &budget,
            "inv-001",
            b"hello",
        )
        .unwrap();
        assert_eq!(evidence.cost_usd_micros, 250_000);
        assert_eq!(evidence.reply_sha256, receipt.reply_sha256);

        assert!(validate_provider_receipt(
            &root,
            &verified,
            &verified.contract.profile_sha256,
            &role,
            &budget,
            "inv-001",
            b"changed",
        )
        .is_err());
    }

    #[test]
    fn charged_model_mismatch_is_valid_evidence_but_never_admitted_output() {
        let (root, verified, role, budget) = receipt_fixture("model-mismatch");
        let receipt = ProviderReceipt {
            schema: RECEIPT_SCHEMA.into(),
            run_contract_sha256: verified.raw_sha256.clone(),
            invocation_id: "inv-001".into(),
            role_id: role.role_id.clone(),
            adapter_id: role.adapter_id.clone(),
            provider_id: role.provider_id.clone(),
            routing_provider: Some("Google AI Studio".into()),
            request_id: "gen-mismatch".into(),
            requested_model: role.requested_model.clone(),
            resolved_model: "google/gemini-4-argon-unexpected".into(),
            raw_usage: serde_json::json!({"cost": 0.50}),
            cost_authority: "measured".into(),
            cost_usd_micros: 500_000,
            raw_cost_usd: Some("0.50".into()),
            reply_sha256: format!("{:x}", Sha256::digest(b"withheld")),
            finish_reason: serde_json::json!("stop"),
        };
        write_receipt(&root, &receipt).unwrap();

        let evidence = validate_provider_receipt_evidence(
            &root,
            &verified,
            &verified.contract.profile_sha256,
            &role,
            &budget,
            "inv-001",
        )
        .unwrap();
        assert_eq!(evidence.resolved_model, receipt.resolved_model);
        assert!(validate_provider_receipt(
            &root,
            &verified,
            &verified.contract.profile_sha256,
            &role,
            &budget,
            "inv-001",
            b"withheld",
        )
        .is_err());
    }

    #[test]
    fn relative_profile_artifacts_resolve_to_absolute_runtime_paths() {
        let root = std::env::temp_dir().join(format!(
            "loop-cycle-portable-profile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let profiles = root.join("profiles");
        let bin = root.join("bin");
        fs::create_dir_all(&profiles).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let argon = bin.join("argon.exe");
        let sonnet = bin.join("sonnet.exe");
        let price = profiles.join("price.json");
        fs::write(&argon, b"argon-wrapper").unwrap();
        fs::write(&sonnet, b"sonnet-wrapper").unwrap();
        fs::write(&price, b"price-manifest").unwrap();
        let argon_sha = format!("{:x}", Sha256::digest(b"argon-wrapper"));
        let sonnet_sha = format!("{:x}", Sha256::digest(b"sonnet-wrapper"));
        let price_sha = format!("{:x}", Sha256::digest(b"price-manifest"));
        let sonnet_role = |role_id: &str, lane: Agent| ProfileRole {
            role_id: role_id.into(),
            scheduler_lane: lane,
            adapter_id: "anthropic-sonnet55-v1".into(),
            provider_id: "anthropic".into(),
            requested_model: "claude-sonnet-5-5".into(),
            normalized_model: "anthropic/claude-sonnet-5-5".into(),
            wrapper_path: PathBuf::from("../bin/sonnet.exe"),
            wrapper_sha256: sonnet_sha.clone(),
            price_manifest_path: Some(PathBuf::from("price.json")),
            price_manifest_sha256: Some(price_sha.clone()),
            receipt_required: true,
        };
        let profile = ExecutionProfile {
            schema: PROFILE_SCHEMA.into(),
            id: "sonnet55-argon4-planning-v1".into(),
            run_mode: "planning".into(),
            telemetry_required: true,
            budgets: vec![
                ProfileBudget {
                    provider_id: "openrouter".into(),
                    cap_usd_micros: 20_000_000,
                    settlement: "measured".into(),
                },
                ProfileBudget {
                    provider_id: "anthropic".into(),
                    cap_usd_micros: 25_000_000,
                    settlement: "derived".into(),
                },
            ],
            roles: vec![
                ProfileRole {
                    role_id: "design_author".into(),
                    scheduler_lane: Agent::Agy,
                    adapter_id: "openrouter-argon-v1".into(),
                    provider_id: "openrouter".into(),
                    requested_model: "google/gemini-4-argon".into(),
                    normalized_model: "google/gemini-4-argon".into(),
                    wrapper_path: PathBuf::from("../bin/argon.exe"),
                    wrapper_sha256: argon_sha.clone(),
                    price_manifest_path: None,
                    price_manifest_sha256: None,
                    receipt_required: true,
                },
                sonnet_role("design_review", Agent::Claude),
                ProfileRole {
                    role_id: "feasibility_review".into(),
                    scheduler_lane: Agent::Codex,
                    adapter_id: "openrouter-argon-v1".into(),
                    provider_id: "openrouter".into(),
                    requested_model: "google/gemini-4-argon".into(),
                    normalized_model: "google/gemini-4-argon".into(),
                    wrapper_path: PathBuf::from("../bin/argon.exe"),
                    wrapper_sha256: argon_sha,
                    price_manifest_path: None,
                    price_manifest_sha256: None,
                    receipt_required: true,
                },
            ],
        };
        let profile_path = profiles.join("profile.json");
        let bytes = serde_json::to_vec_pretty(&profile).unwrap();
        fs::write(&profile_path, &bytes).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));

        let loaded = load_execution_profile(&profile_path, &digest).unwrap();
        assert_eq!(
            loaded.roles[0].wrapper_path,
            fs::canonicalize(argon).unwrap()
        );
        assert_eq!(
            loaded.roles[1].price_manifest_path.as_deref(),
            Some(fs::canonicalize(price).unwrap().as_path())
        );
    }
}

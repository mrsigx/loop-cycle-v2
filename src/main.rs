//! `loop-cycle`: the v2 conductor. Foreground only; the operator starts every cycle.
//!
//!   loop-cycle run --task <file> --repo <dir> --scratch-root <dir> --base <dir> [--design <file>]
//!                  [--lease-helper <ps1>] [--swarm ask|auto|off] [--caps <agy>,<claude>,<codex>]
//!                  [--total <n>] [--wall-mins <n>] [--step-mins <n>] [--impl-mins <n>]
//!                  [--canary-file <file>] [--cycle-id <id>]
//!                  [--agy <exe>] [--claude <exe>] [--codex <exe>] [--nl-cycle <wsl path>]
//!                  [--codex-model <id>]   (default gpt-6-astra)
//!                  [--plan-rounds <n>] [--brief-rounds <n>] [--impl-rounds <n>]   (defaults 4, 2, 3)
//!   loop-cycle status <cycle-dir>
//!   loop-cycle park <cycle-dir>
//!   loop-cycle reconcile <cycle-dir>
//!   loop-cycle resume <cycle-dir> [--canary-file <file>]
//!
//! Until admission gates S1–S9 pass, `run` refuses any repository outside a marked scratch root.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use loop_cycle::cycle::{self, CycleDir};
use loop_cycle::driver::{self, Console, Run};
use loop_cycle::machine::{Config, Counts, RunMode, SwarmMode};
use loop_cycle::protocol;
use loop_cycle::templates::Tools;

fn usage() -> ExitCode {
    eprintln!("usage: loop-cycle run --task <file> --repo <dir> --scratch-root <dir> [--mode full|planning] [options] | capabilities --json | status [--json] <cycle-dir> | park|reconcile <cycle-dir>");
    ExitCode::from(64)
}

fn flags(args: &[String]) -> Option<HashMap<String, String>> {
    let mut m = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let k = k.strip_prefix("--")?;
        m.insert(k.to_string(), it.next()?.clone());
    }
    Some(m)
}

fn find_exe(name: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("where.exe")
        .arg(name)
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| PathBuf::from(l.trim()))
}

fn run(args: &[String]) -> ExitCode {
    let Some(f) = flags(args) else { return usage() };
    let (Some(task), Some(repo), Some(scratch)) =
        (f.get("task"), f.get("repo"), f.get("scratch-root"))
    else {
        return usage();
    };
    let num = |k: &str, d: u64| f.get(k).map(|v| v.parse::<u64>().ok()).unwrap_or(Some(d));
    let (Some(wall), Some(step), Some(imp), Some(total)) = (
        num("wall-mins", 90),
        num("step-mins", 15),
        num("impl-mins", 40),
        num("total", 24),
    ) else {
        return usage();
    };
    let caps: Vec<u32> = f
        .get("caps")
        .map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
        .unwrap_or(vec![8, 12, 8]);
    let defaults = Config::default();
    let (Some(plan_rounds), Some(brief_rounds), Some(impl_rounds)) = (
        num("plan-rounds", defaults.plan_rounds as u64),
        num("brief-rounds", defaults.brief_rounds as u64),
        num("impl-rounds", defaults.impl_rounds as u64),
    ) else {
        return usage();
    };
    if caps.len() != 3
        || [
            wall,
            step,
            imp,
            total,
            plan_rounds,
            brief_rounds,
            impl_rounds,
        ]
        .contains(&0)
    {
        return usage();
    }
    let swarm = match f.get("swarm").map(String::as_str).unwrap_or("ask") {
        "ask" => SwarmMode::Ask,
        "auto" => SwarmMode::Auto,
        "off" => SwarmMode::Off,
        _ => return usage(),
    };
    let run_mode = match f.get("mode").map(String::as_str).unwrap_or("full") {
        "full" => RunMode::Full,
        "planning" => RunMode::Planning,
        _ => return usage(),
    };
    if run_mode == RunMode::Planning && f.contains_key("brief") {
        eprintln!("planning mode refuses --brief because imported briefs bypass planning");
        return ExitCode::from(2);
    }
    let (profile, profile_sha256) = match (f.get("profile"), f.get("profile-sha256")) {
        (None, None) => (None, None),
        (Some(path), Some(digest)) => {
            match loop_cycle::provider::load_execution_profile(Path::new(path), digest) {
                Ok(profile) => (Some(profile), Some(digest.to_ascii_lowercase())),
                Err(e) => {
                    eprintln!("profile refused: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!("--profile and --profile-sha256 must be supplied together");
            return ExitCode::from(2);
        }
    };
    if profile.is_some() && (run_mode != RunMode::Planning || swarm != SwarmMode::Off) {
        eprintln!("paid execution profiles are planning-only and require --swarm off");
        return ExitCode::from(2);
    }
    let tool = |k: &str, exe: &str| f.get(k).map(PathBuf::from).or_else(|| find_exe(exe));
    let profile_tool = |role_id: &str| {
        profile
            .as_ref()
            .and_then(|p| p.roles.iter().find(|r| r.role_id == role_id))
            .map(|r| r.wrapper_path.clone())
    };
    let (Some(agy), Some(claude), Some(codex)) = (
        profile_tool("design_author").or_else(|| tool("agy", "agy")),
        profile_tool("design_review").or_else(|| tool("claude", "claude")),
        profile_tool("feasibility_review").or_else(|| tool("codex", "codex")),
    ) else {
        eprintln!("could not find agy, claude and codex; pass --agy, --claude and --codex");
        return ExitCode::from(2);
    };
    let canaries = match canaries_from(&f) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let cycle_id = f.get("cycle-id").cloned().unwrap_or_else(|| {
        format!(
            "lc-{}",
            cycle::utc_now().replace([':', '.'], "").replace('-', "")
        )
    });
    let Some(base) = f
        .get("base")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOOP_CYCLE_BASE").map(PathBuf::from))
    else {
        eprintln!("--base <dir> (or LOOP_CYCLE_BASE) is required and must sit outside the target repository");
        return ExitCode::from(2);
    };
    let lease_helper = match f
        .get("lease-helper")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOOP_CYCLE_LEASE_HELPER").map(PathBuf::from))
    {
        Some(p) => p,
        None => {
            eprintln!("--lease-helper <ps1> (or LOOP_CYCLE_LEASE_HELPER) is required");
            return ExitCode::from(2);
        }
    };
    let r = Run {
        cycle_id,
        task: PathBuf::from(task),
        repo_win: PathBuf::from(repo),
        design: f.get("design").map(PathBuf::from),
        brief: f.get("brief").map(PathBuf::from),
        machine: Config {
            swarm,
            caps: Counts::new(caps[0], caps[1], caps[2]),
            total_cap: total as u32,
            plan_rounds: plan_rounds as u32,
            brief_rounds: brief_rounds as u32,
            impl_rounds: impl_rounds as u32,
            run_mode,
            ..defaults
        },
        wall: Duration::from_secs(wall * 60),
        step_deadline: Duration::from_secs(step * 60),
        impl_deadline: Duration::from_secs(imp * 60),
        base,
        account: std::env::var("USERNAME").unwrap_or_default(),
        tools: Tools {
            agy,
            claude,
            codex,
            nl_cycle_wsl: f
                .get("nl-cycle")
                .cloned()
                .or_else(|| std::env::var("LOOP_CYCLE_BACKEND_WSL").ok())
                .unwrap_or_else(|| "nl-cycle".into()),
            codex_model: f
                .get("codex-model")
                .cloned()
                .unwrap_or_else(|| "gpt-6-astra".into()),
        },
        canaries,
        scratch_root: PathBuf::from(scratch),
        lease_helper,
        profile,
        profile_sha256,
    };
    let mut console = Console::new();
    match driver::drive(&r, &mut console) {
        Ok(t) => {
            println!("terminal: {t:?}");
            if t.is_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("refused or failed: {e:?}");
            ExitCode::from(2)
        }
    }
}

fn status(dir: &Path) -> ExitCode {
    match cycle::verify_events(&dir.join("events.jsonl")) {
        Ok(n) => println!("events.jsonl: chain OK, {n} events"),
        Err(e) => println!("events.jsonl: {e}"),
    }
    match std::fs::read_to_string(dir.join("state.json")) {
        Ok(s) => print!("{s}"),
        Err(e) => println!("state.json: {e}"),
    }
    ExitCode::SUCCESS
}

fn status_json(dir: &Path) -> ExitCode {
    let (value, ok) = protocol::status_envelope(dir);
    match serde_json::to_string_pretty(&value) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("status serialization failed: {e}");
            return ExitCode::from(2);
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn capabilities_json() -> ExitCode {
    match serde_json::to_string_pretty(&protocol::capabilities()) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("capabilities serialization failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn preflight_json(args: &[String]) -> ExitCode {
    let Some(f) = flags(args) else { return usage() };
    let (Some(profile), Some(digest)) = (f.get("profile"), f.get("profile-sha256")) else {
        return usage();
    };
    let value = loop_cycle::provider::profile_preflight(Path::new(profile), digest);
    let ok = value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    match serde_json::to_string_pretty(&value) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("preflight serialization failed: {e}");
            return ExitCode::from(2);
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn park(dir: &Path) -> ExitCode {
    match std::fs::write(dir.join("PARK"), b"park requested by the operator\n") {
        Ok(()) => {
            println!("park requested: the running invocation ends within about a second");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

/// After a crash: confirms every WSL namespace the cycle recorded is empty, and records that.
/// Windows trees die with the conductor's Job Object handles; Linux namespaces are checked here.
fn reconcile(dir: &Path) -> ExitCode {
    let mut c = match CycleDir::open(dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot reopen the cycle: {e:?}");
            return ExitCode::from(2);
        }
    };
    let report = driver::namespace_report(dir);
    let all_empty = report.iter().all(|(_, _, live)| *live == 0);
    let rows: Vec<_> = report
        .iter()
        .map(|(f, ns, live)| serde_json::json!({"file": f.to_string_lossy(), "namespace": ns, "live": live}))
        .collect();
    let kind = if all_empty {
        "reconcile_confirmed"
    } else {
        "reconcile_unconfirmed"
    };
    if let Err(e) = c.event(kind, serde_json::json!({"namespaces": rows}), &[]) {
        eprintln!("could not record: {e:?}");
        return ExitCode::from(2);
    }
    println!("{kind}: {} namespace file(s) checked", report.len());
    if all_empty {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn canaries_from(f: &HashMap<String, String>) -> Result<Vec<String>, String> {
    match f.get("canary-file") {
        Some(p) => std::fs::read_to_string(p)
            .map(|t| {
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect()
            })
            .map_err(|e| format!("canary file: {e}")),
        None => Ok(Vec::new()),
    }
}

fn resume(dir: &Path, rest: &[String]) -> ExitCode {
    let Some(f) = flags(rest) else { return usage() };
    let canaries = match canaries_from(&f) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut console = Console::new();
    match driver::resume(dir, canaries, &mut console) {
        Ok(t) => {
            println!("terminal: {t:?}");
            if t.is_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("refused or failed: {e:?}");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((cmd, rest)) if cmd == "run" => run(rest),
        Some((cmd, rest)) if cmd == "capabilities" && rest == ["--json"] => capabilities_json(),
        Some((cmd, rest)) if cmd == "preflight" && !rest.is_empty() && rest[0] == "--json" => {
            preflight_json(&rest[1..])
        }
        Some((cmd, rest)) if cmd == "status" && rest.len() == 2 && rest[0] == "--json" => {
            status_json(Path::new(&rest[1]))
        }
        Some((cmd, rest)) if cmd == "status" && rest.len() == 1 => status(Path::new(&rest[0])),
        Some((cmd, rest)) if cmd == "park" && rest.len() == 1 => park(Path::new(&rest[0])),
        Some((cmd, rest)) if cmd == "reconcile" && rest.len() == 1 => {
            reconcile(Path::new(&rest[0]))
        }
        Some((cmd, rest)) if cmd == "resume" && !rest.is_empty() => {
            resume(Path::new(&rest[0]), &rest[1..])
        }
        _ => usage(),
    }
}

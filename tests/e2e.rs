//! No-cost end-to-end tests of the driver (`cargo test --features fakes -- --test-threads=1`):
//! real cycle folders, real contained launches, a real target lease, real Git in WSL, with
//! scripted fake agents and a fake nl-cycle. These rehearse S3/S5/S6/S7 paths; they are not the
//! live gates, which need the real CLIs and the real nl-cycle.
#![cfg(feature = "fakes")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use loop_cycle::cycle;
use loop_cycle::driver::{self, Answer, DriveError, Operator, Run, SCRATCH_MARKER};
use loop_cycle::machine::{Config, Event, SwarmMode, Terminal};
use loop_cycle::templates::Tools;
use loop_cycle::wsl;

const CANARY: &str = "LCCANARY-e2e-5b1d0c";

fn scratch_base() -> PathBuf {
    let target_base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
    target_base.join("e2e-scratch")
}

fn test_lease_helper() -> PathBuf {
    let dir = scratch_base().join("leases");
    std::fs::create_dir_all(&dir).unwrap();
    let dst = dir.join("lease.ps1");
    if !dst.exists() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts")
            .join("lease.ps1");
        std::fs::copy(&src, &dst).unwrap();
    }
    dst
}

struct Scripted(Vec<bool>);

impl Operator for Scripted {
    fn ask(&mut self, _q: &str, _until: Instant, _park: &Path) -> Answer {
        if self.0.is_empty() {
            return Answer::Stop(Event::Cancel);
        }
        if self.0.remove(0) {
            Answer::Yes
        } else {
            Answer::No
        }
    }
}

fn wsl_sh(script: &str, args: &[&str]) {
    let out = Command::new("wsl.exe")
        .args(["-e", "/bin/bash", "-c", script, "t"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const FAKE_NL_CYCLE: &str = r#"#!/bin/bash
here="$(dirname "$0")"
cmd=$1; shift
case "$cmd" in
  implement) brief=$1; shift; [ "$1" = --repo ] && repo=$2
             if [ -e "$here/sleep-implement" ] && [ ! -e "$here/slept" ]; then : > "$here/slept"; sleep 120; fi
             echo "change $(date +%s%N)" >> "$repo/feature.txt"
             if [ -e "$here/canary-text" ]; then cat "$here/canary.txt" >> "$repo/feature.txt"; fi
             if [ -e "$here/canary-base64" ]; then base64 -w0 "$here/canary.txt" >> "$repo/feature.txt"; fi
             if [ -e "$here/canary-binary" ]; then { printf '\000\001'; cat "$here/canary.txt"; printf '\000'; } > "$repo/data.bin"; fi
             if [ -e "$here/canary-gzip" ]; then gzip -cn "$here/canary.txt" > "$repo/data.gz"; fi
             echo implemented;;
  bundle) while [ $# -gt 0 ]; do case $1 in --repo) repo=$2; shift 2;; --output) out=$2; shift 2;; *) shift;; esac; done
          if [ -e "$here/drift" ]; then echo late >> "$repo/feature.txt"; fi
          echo '{"fake": true}' > "$out";;
  verify) exit 0;;
  *) exit 64;;
esac
"#;

struct Fixture {
    root: PathBuf,
    repo: PathBuf,
    state: PathBuf,
    script: PathBuf,
    nl_cycle_wsl: String,
}

fn fixture(name: &str) -> Fixture {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = scratch_base();
    std::fs::create_dir_all(&scratch).unwrap();
    let _ = test_lease_helper();
    let marker = scratch.join(SCRATCH_MARKER);
    if !marker.exists() {
        std::fs::write(&marker, b"Scratch root for loop-cycle v2 gate runs. Nothing here is a real repository.\n").unwrap();
    }
    let root = scratch.join(format!("e2e-{name}-{stamp}"));
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let repo_wsl = wsl::to_wsl_path(&repo).unwrap();
    wsl_sh(
        r#"cd "$1" && git init -q -b main && git config user.email t@example.invalid && git config user.name t && echo base > README.md && git add README.md && git -c commit.gpgsign=false commit -qm base"#,
        &[&repo_wsl],
    );
    let state = root.join("fake-state");
    std::fs::create_dir_all(&state).unwrap();
    let tools = root.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let nl = tools.join("nl-cycle");
    std::fs::write(&nl, FAKE_NL_CYCLE.replace("\r\n", "\n")).unwrap();
    let nl_cycle_wsl = wsl::to_wsl_path(&nl).unwrap();
    let real_src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("nl-cycle-bundler.sh");
    let real_dst = tools.join("nl-cycle-real");
    let real_bytes = std::fs::read_to_string(&real_src)
        .unwrap()
        .replace("\r\n", "\n");
    std::fs::write(&real_dst, real_bytes).unwrap();
    let real_wsl = wsl::to_wsl_path(&real_dst).unwrap();
    wsl_sh(r#"chmod +x "$1" "$2""#, &[&nl_cycle_wsl, &real_wsl]);
    std::fs::write(tools.join("canary.txt"), CANARY).unwrap();
    Fixture {
        script: root.join("script.json"),
        root,
        repo,
        state,
        nl_cycle_wsl,
    }
}

impl Fixture {
    /// Switches on one of the fake nl-cycle's modes (a marker file beside it).
    fn mode(&self, name: &str) {
        std::fs::write(self.root.join("tools").join(name), b"1").unwrap();
    }
}

fn run_for(f: &Fixture, swarm: SwarmMode) -> Run {
    let fake = PathBuf::from(env!("CARGO_BIN_EXE_lc-fake-agent"));
    Run {
        cycle_id: "lc-e2e".into(),
        task: {
            let t = f.root.join("task.md");
            std::fs::write(&t, b"# Task\n\nAdd a line to feature.txt.\n").unwrap();
            t
        },
        repo_win: f.repo.clone(),
        design: None,
        brief: None,
        machine: Config {
            swarm,
            ..Config::default()
        },
        wall: Duration::from_secs(600),
        step_deadline: Duration::from_secs(60),
        impl_deadline: Duration::from_secs(120),
        base: f.root.join("cycles"),
        account: std::env::var("USERNAME").unwrap(),
        tools: Tools {
            agy: fake.clone(),
            claude: fake.clone(),
            codex: fake,
            nl_cycle_wsl: f.nl_cycle_wsl.clone(),
            codex_model: "gpt-6-astra".into(),
        },
        canaries: vec![CANARY.into()],
        scratch_root: scratch_base(),
        lease_helper: test_lease_helper(),
        profile: None,
        profile_sha256: None,
    }
}

fn go(
    f: &Fixture,
    script: &str,
    swarm: SwarmMode,
    answers: Vec<bool>,
) -> (Result<Terminal, DriveError>, PathBuf) {
    std::fs::write(&f.script, script).unwrap();
    std::env::set_var("LC_FAKE_SCRIPT", &f.script);
    std::env::set_var("LC_FAKE_STATE", &f.state);
    std::env::set_var("LC_FAKE_CANARY", CANARY);
    let run = run_for(f, swarm);
    let cycle_dir = run.base.join(&run.cycle_id);
    std::fs::create_dir_all(&run.base).unwrap();
    let result = driver::drive(&run, &mut Scripted(answers));
    (result, cycle_dir)
}

fn events(cycle_dir: &Path) -> String {
    std::fs::read_to_string(cycle_dir.join("events.jsonl")).unwrap()
}

fn no_live_lease_on(repo: &Path) {
    let helper = test_lease_helper();
    let reg = helper.parent().unwrap();
    let common = repo.join(".git").to_string_lossy().to_ascii_lowercase();
    for e in std::fs::read_dir(reg).unwrap().flatten() {
        if e.file_name().to_string_lossy().ends_with(".lease") {
            let t = std::fs::read_to_string(e.path().join("lease.json"))
                .unwrap_or_default()
                .to_ascii_lowercase();
            assert!(
                !t.contains(&common.replace('\\', "\\\\")),
                "the target lease was left behind: {}",
                e.path().display()
            );
        }
    }
}

#[test]
fn direct_cycle_reaches_bundle_verified_and_releases_the_target() {
    let f = fixture("direct");
    let (r, dir) = go(&f, "{}", SwarmMode::Ask, vec![true]);
    assert_eq!(r.unwrap(), Terminal::BundleVerifiedAwaitingOperatorSign);
    assert!(cycle::verify_events(&dir.join("events.jsonl")).unwrap() > 10);
    let ev = events(&dir);
    for kind in [
        "\"start\"",
        "\"artifact\"",
        "\"review\"",
        "\"manifest\"",
        "\"bundle\"",
        "\"stop\"",
    ] {
        assert!(ev.contains(kind), "missing {kind}");
    }
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest-1.json")).unwrap())
            .unwrap();
    assert_eq!(m["entries"][0]["path"], "feature.txt");
    assert_eq!(m["entries"][0]["action"], "add");
    // On a /mnt drive every file looks executable; the manifest must still report Git's mode (S5 finding).
    assert_eq!(m["entries"][0]["mode"], "100644");
    assert!(dir.join("bundle").join("manifest.json").exists());
    no_live_lease_on(&f.repo);
}

#[test]
fn a_secret_in_a_reply_is_quarantined_and_parks() {
    let f = fixture("secret");
    let (r, dir) = go(
        &f,
        r#"{"claude:design_review": ["secret"]}"#,
        SwarmMode::Ask,
        vec![],
    );
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    let q: Vec<_> = std::fs::read_dir(dir.join("quarantine"))
        .unwrap()
        .flatten()
        .collect();
    assert!(!q.is_empty());
    // The canary survives only in quarantine, never in the stage, a stored artifact or the log.
    for e in walk(&dir) {
        if e.starts_with(dir.join("quarantine")) {
            continue;
        }
        let bytes = std::fs::read(&e).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(CANARY),
            "canary leaked into {}",
            e.display()
        );
    }
    no_live_lease_on(&f.repo);
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(d).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn a_reply_without_a_valid_result_parks_as_invalid() {
    let f = fixture("garbage");
    let (r, dir) = go(
        &f,
        r#"{"claude:design_review": ["garbage"]}"#,
        SwarmMode::Ask,
        vec![],
    );
    assert_eq!(r.unwrap(), Terminal::ParkedInvalid);
    assert!(events(&dir).contains("invalid_result"));
}

#[test]
fn a_change_after_review_is_drift() {
    let f = fixture("drift");
    std::fs::write(f.root.join("tools").join("drift"), b"1").unwrap();
    let (r, _) = go(&f, "{}", SwarmMode::Ask, vec![true]);
    assert_eq!(r.unwrap(), Terminal::ParkedDrift);
}

#[test]
fn the_operator_can_refuse_the_allowlist() {
    let f = fixture("refuse");
    let (r, _) = go(&f, "{}", SwarmMode::Ask, vec![false]);
    assert_eq!(r.unwrap(), Terminal::ParkedRejected);
}

#[test]
fn a_complex_design_goes_through_swarm_and_the_operator_accepts_the_merge() {
    let f = fixture("swarm");
    let (r, dir) = go(
        &f,
        r#"{"agy:design": ["cx5"]}"#,
        SwarmMode::Auto,
        vec![true, true],
    );
    assert_eq!(r.unwrap(), Terminal::BundleVerifiedAwaitingOperatorSign);
    for c in [
        "candidate-agy.md",
        "candidate-claude.md",
        "candidate-codex.md",
        "M.md",
    ] {
        assert!(dir.join(c).exists(), "missing {c}");
    }
}

#[test]
fn real_repositories_are_not_admitted() {
    let f = fixture("guard");
    let mut run = run_for(&f, SwarmMode::Ask);
    run.repo_win = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(matches!(
        driver::drive(&run, &mut Scripted(vec![])),
        Err(DriveError::NotAdmitted(_))
    ));
    let mut run = run_for(&f, SwarmMode::Ask);
    run.scratch_root = f.root.clone(); // unmarked
    assert!(matches!(
        driver::drive(&run, &mut Scripted(vec![])),
        Err(DriveError::NotAdmitted(_))
    ));
}

#[test]
fn a_dirty_working_tree_is_refused() {
    let f = fixture("dirty");
    std::fs::write(f.repo.join("stray.txt"), b"x").unwrap();
    let run = run_for(&f, SwarmMode::Ask);
    assert!(matches!(
        driver::drive(&run, &mut Scripted(vec![])),
        Err(DriveError::Repo(_))
    ));
}

// ---------------------------------------------------------------- S7: more secret paths

/// No file in the cycle folder outside quarantine holds the canary.
fn canary_only_in_quarantine(dir: &Path) {
    for e in walk(dir) {
        if e.starts_with(dir.join("quarantine")) {
            continue;
        }
        let bytes = std::fs::read(&e).unwrap();
        assert!(
            !bytes.windows(CANARY.len()).any(|w| w == CANARY.as_bytes()),
            "canary leaked into {}",
            e.display()
        );
    }
}

#[test]
fn s7_a_canary_written_into_the_repository_never_reaches_a_reviewer() {
    let f = fixture("s7-repo");
    f.mode("canary-text");
    let (r, dir) = go(&f, "{}", SwarmMode::Ask, vec![true]);
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    assert!(
        !events(&dir).contains("diff-review"),
        "no diff review was launched"
    );
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_a_canary_in_a_binary_file_is_caught_by_the_byte_scan() {
    let f = fixture("s7-binary");
    f.mode("canary-binary");
    let (r, dir) = go(&f, "{}", SwarmMode::Ask, vec![true]);
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_a_base64_encoded_canary_in_the_repository_parks_before_review() {
    let f = fixture("s7-base64");
    f.mode("canary-base64");
    let (r, dir) = go(&f, "{}", SwarmMode::Ask, vec![true]);
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    assert!(!events(&dir).contains("diff-review"));
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_a_gzipped_synthetic_canary_parks_as_opaque_before_review() {
    let f = fixture("s7-gzip");
    f.mode("canary-gzip");
    let (r, dir) = go(&f, "{}", SwarmMode::Ask, vec![true]);
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    assert!(!events(&dir).contains("diff-review"));
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_a_canary_on_stderr_is_quarantined() {
    let f = fixture("s7-stderr");
    let (r, dir) = go(
        &f,
        r#"{"claude:design_review": ["stderr-secret"]}"#,
        SwarmMode::Ask,
        vec![],
    );
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_nonzero_exit_captures_stderr_before_result_classification() {
    let f = fixture("s7-stderr-exit1");
    let (r, dir) = go(
        &f,
        r#"{"claude:design_review": ["stderr-secret-exit1"]}"#,
        SwarmMode::Ask,
        vec![],
    );
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    assert!(events(&dir).contains("Exited(1)"));
    canary_only_in_quarantine(&dir);
}

#[test]
fn s1_output_limit_parks_and_only_quarantine_receives_the_retained_prefix() {
    let f = fixture("s1-output-limit");
    let (result, dir) = go(
        &f,
        r#"{"claude:design_review": ["output-limit"]}"#,
        SwarmMode::Ask,
        vec![],
    );

    assert_eq!(result.unwrap(), Terminal::ParkedOutputLimit);
    let log = events(&dir);
    assert!(log.contains("OutputLimitExceeded"));
    assert!(log.contains("\"kind\":\"secret\""));
    assert!(log.contains("\"limit_bytes\":16777216"));
    assert!(log.contains("\"capture_complete\":false"));
    let overflow_stage = std::fs::read_dir(dir.join("stages"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|stage| {
            stage
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains("design_review-claude"))
        })
        .expect("overflowing review stage");
    assert_eq!(
        std::fs::read(overflow_stage.join("stdout.txt")).unwrap(),
        b"[moved to quarantine]\n"
    );
    assert!(std::fs::read_dir(dir.join("quarantine"))
        .unwrap()
        .flatten()
        .any(|entry| entry.metadata().map(|m| m.len() > 0).unwrap_or(false)));
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_a_base64_canary_in_a_reply_is_quarantined() {
    let f = fixture("s7-reply-base64");
    let (r, dir) = go(
        &f,
        r#"{"claude:design_review": ["secret-base64"]}"#,
        SwarmMode::Ask,
        vec![],
    );
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_a_base64_canary_on_stderr_is_quarantined() {
    let f = fixture("s7-stderr-base64");
    let (r, dir) = go(
        &f,
        r#"{"claude:design_review": ["stderr-secret-base64"]}"#,
        SwarmMode::Ask,
        vec![],
    );
    assert_eq!(r.unwrap(), Terminal::ParkedSecret);
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_timeout_captures_stderr_before_any_stage_write() {
    let f = fixture("s7-timeout-stderr");
    std::fs::write(&f.script, r#"{"agy:design": ["stderr-secret-sleep"]}"#).unwrap();
    std::env::set_var("LC_FAKE_SCRIPT", &f.script);
    std::env::set_var("LC_FAKE_STATE", &f.state);
    std::env::set_var("LC_FAKE_CANARY", CANARY);
    let mut run = run_for(&f, SwarmMode::Ask);
    run.step_deadline = Duration::from_secs(2);
    let dir = run.base.join(&run.cycle_id);
    assert_eq!(
        driver::drive(&run, &mut Scripted(vec![])).unwrap(),
        Terminal::ParkedSecret
    );
    assert!(events(&dir).contains("Deadline"));
    canary_only_in_quarantine(&dir);
}

#[test]
fn s7_park_captures_stdout_before_any_stage_write() {
    let f = fixture("s7-park-stdout");
    std::fs::write(&f.script, r#"{"agy:design": ["stdout-secret-sleep"]}"#).unwrap();
    std::env::set_var("LC_FAKE_SCRIPT", &f.script);
    std::env::set_var("LC_FAKE_STATE", &f.state);
    std::env::set_var("LC_FAKE_CANARY", CANARY);
    let run = run_for(&f, SwarmMode::Ask);
    let dir = run.base.join(&run.cycle_id);
    let count = f.state.join("agy_design.count");
    let park = dir.join("PARK");
    let request = std::thread::spawn(move || {
        for _ in 0..200 {
            if count.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(count.exists(), "fake agent was not launched");
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(park, b"park").unwrap();
    });
    let result = driver::drive(&run, &mut Scripted(vec![]));
    request.join().unwrap();
    assert_eq!(result.unwrap(), Terminal::ParkedSecret);
    assert!(events(&dir).contains("ParkRequested"));
    canary_only_in_quarantine(&dir);
}

// ---------------------------------------------------------------- S9: ownership

/// A lease held by another lane for the test's duration, released on drop.
struct HeldLease {
    root: PathBuf,
    lane: String,
}

impl HeldLease {
    fn take(root: &Path) -> HeldLease {
        let helper = test_lease_helper();
        let lane = format!(
            "lc-test:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let out = Command::new("pwsh")
            .args(["-NoProfile", "-File"])
            .arg(&helper)
            .args(["-Action", "acquire", "-Root"])
            .arg(root)
            .args([
                "-LaneId",
                &lane,
                "-Scope",
                "loop-cycle S9 test: another lane holds this root",
                "-Boundary",
                "loop-cycle-v2-scratch-only-admission",
            ])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("LEASE ACQUIRED"),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        HeldLease {
            root: root.to_path_buf(),
            lane,
        }
    }
}

impl Drop for HeldLease {
    fn drop(&mut self) {
        let helper = test_lease_helper();
        let _ = Command::new("pwsh")
            .args(["-NoProfile", "-File"])
            .arg(&helper)
            .args(["-Action", "release", "-Root"])
            .arg(&self.root)
            .args(["-LaneId", &self.lane])
            .output();
    }
}

fn refused_for_lease(run: &Run) {
    match driver::drive(run, &mut Scripted(vec![])) {
        Err(DriveError::Lease(_)) => {}
        other => panic!("expected a lease refusal, got {other:?}"),
    }
}

#[test]
fn s9_a_second_conductor_on_the_same_repository_is_refused() {
    let f = fixture("s9-second");
    std::fs::write(&f.script, r#"{"claude:design_review": ["sleep"]}"#).unwrap();
    std::env::set_var("LC_FAKE_SCRIPT", &f.script);
    std::env::set_var("LC_FAKE_STATE", &f.state);
    std::env::set_var("LC_FAKE_CANARY", CANARY);
    let first = run_for(&f, SwarmMode::Ask);
    let first_dir = first.base.join(&first.cycle_id);
    std::fs::create_dir_all(&first.base).unwrap();
    let handle = std::thread::spawn(move || driver::drive(&first, &mut Scripted(vec![])));
    // Wait until the first conductor holds the target and is inside its sleeping review.
    let t0 = Instant::now();
    while !std::fs::read_to_string(first_dir.join("events.jsonl"))
        .unwrap_or_default()
        .contains("design_review")
    {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "the first cycle never reached its review"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut second = run_for(&f, SwarmMode::Ask);
    second.cycle_id = "lc-e2e-second".into();
    refused_for_lease(&second);
    // A park request ends the first cycle's sleeping invocation within about a second.
    std::fs::write(first_dir.join("PARK"), b"park").unwrap();
    assert_eq!(handle.join().unwrap().unwrap(), Terminal::Cancelled);
    no_live_lease_on(&f.repo);
}

#[test]
fn s9_a_linked_worktree_shares_the_lease_key() {
    let f = fixture("s9-worktree");
    let repo_wsl = wsl::to_wsl_path(&f.repo).unwrap();
    wsl_sh(
        r#"cd "$1" && git worktree add -q ../wt -b wt"#,
        &[&repo_wsl],
    );
    let _held = HeldLease::take(&f.repo.join(".git"));
    let mut run = run_for(&f, SwarmMode::Ask);
    run.repo_win = f.root.join("wt");
    refused_for_lease(&run);
}

#[test]
fn s9_a_path_alias_is_the_same_target() {
    let f = fixture("s9-alias");
    let _held = HeldLease::take(&f.repo.join(".git"));
    let mut run = run_for(&f, SwarmMode::Ask);
    run.repo_win = PathBuf::from(f.repo.to_string_lossy().to_lowercase());
    refused_for_lease(&run);
}

#[test]
fn s9_another_lanes_lease_over_the_worktree_wins() {
    let f = fixture("s9-parent");
    let _held = HeldLease::take(&f.root);
    refused_for_lease(&run_for(&f, SwarmMode::Ask));
}

#[test]
fn s9_resume_is_refused_while_a_namespace_is_live() {
    let f = fixture("s9-live-ns");
    // A cycle stopped mid-design-review by a park request, then a live namespace planted in it.
    std::fs::write(&f.script, r#"{"claude:design_review": ["sleep", "pass"]}"#).unwrap();
    std::env::set_var("LC_FAKE_SCRIPT", &f.script);
    std::env::set_var("LC_FAKE_STATE", &f.state);
    std::env::set_var("LC_FAKE_CANARY", CANARY);
    let run = run_for(&f, SwarmMode::Ask);
    let dir = run.base.join(&run.cycle_id);
    std::fs::create_dir_all(&run.base).unwrap();
    let ns_file = dir.join("ns-live.txt");
    let ns_wsl = wsl::to_wsl_path(&ns_file).unwrap();
    let handle = std::thread::spawn(move || driver::drive(&run, &mut Scripted(vec![])));
    let t0 = Instant::now();
    while !std::fs::read_to_string(dir.join("events.jsonl"))
        .unwrap_or_default()
        .contains("design_review")
    {
        assert!(t0.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut live = Command::new("wsl.exe")
        .args([
            "-e",
            "/usr/bin/unshare",
            "--map-current-user",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "/bin/sh",
            "-c",
            r#"readlink /proc/self/ns/pid > "$1"; exec sleep 60"#,
            "t",
            &ns_wsl,
        ])
        .spawn()
        .unwrap();
    while wsl::recorded_namespace(&ns_file).is_none() {
        assert!(t0.elapsed() < Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(200));
    }
    std::fs::write(dir.join("PARK"), b"park").unwrap();
    assert_eq!(handle.join().unwrap().unwrap(), Terminal::Cancelled);
    let refused = driver::resume(&dir, vec![CANARY.into()], &mut Scripted(vec![]));
    let _ = live.kill();
    let _ = live.wait();
    match refused {
        Err(DriveError::Repo(m)) => assert!(m.contains("termination unconfirmed"), "{m}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------- S8: crash, reconcile, resume

fn fake_processes_running() -> usize {
    let fake = env!("CARGO_BIN_EXE_lc-fake-agent").replace('\'', "''");
    let q = format!("@(Get-CimInstance Win32_Process | Where-Object {{ $_.ExecutablePath -eq '{fake}' }}).Count");
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &q])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

fn conductor(f: &Fixture, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_loop-cycle"));
    c.args(args)
        .env("LC_FAKE_SCRIPT", &f.script)
        .env("LC_FAKE_STATE", &f.state)
        .env("LC_FAKE_CANARY", CANARY)
        .env("LOOP_CYCLE_LEASE_HELPER", test_lease_helper());
    c
}

fn crash_then_resume(name: &str, script: &str, mode: Option<&str>, wait_for: &str) {
    let f = fixture(name);
    std::fs::write(&f.script, script).unwrap();
    if let Some(m) = mode {
        f.mode(m);
    }
    let canary_file = f.root.join("canaries.txt");
    std::fs::write(&canary_file, CANARY).unwrap();
    let task = f.root.join("task.md");
    std::fs::write(&task, b"# Task\n\nAdd a line to feature.txt.\n").unwrap();
    let base = f.root.join("cycles");
    let fake = env!("CARGO_BIN_EXE_lc-fake-agent");
    let scratch_s = scratch_base().to_string_lossy().to_string();
    let (repo, base_s, task_s, canary_s) = (
        f.repo.to_string_lossy().to_string(),
        base.to_string_lossy().to_string(),
        task.to_string_lossy().to_string(),
        canary_file.to_string_lossy().to_string(),
    );
    let mut child = conductor(
        &f,
        &[
            "run",
            "--task",
            &task_s,
            "--repo",
            &repo,
            "--scratch-root",
            &scratch_s,
            "--base",
            &base_s,
            "--cycle-id",
            "lc-crash",
            "--swarm",
            "off",
            "--wall-mins",
            "20",
            "--step-mins",
            "4",
            "--impl-mins",
            "4",
            "--agy",
            fake,
            "--claude",
            fake,
            "--codex",
            fake,
            "--nl-cycle",
            &f.nl_cycle_wsl,
            "--canary-file",
            &canary_s,
        ],
    )
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn()
    .unwrap();
    let dir = base.join("lc-crash");
    let t0 = Instant::now();
    while !std::fs::read_to_string(dir.join("events.jsonl"))
        .unwrap_or_default()
        .contains(wait_for)
    {
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "never reached {wait_for}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    std::thread::sleep(Duration::from_secs(2));
    // The crash: the conductor is killed outright, as by a closed terminal or a fault.
    child.kill().unwrap();
    let _ = child.wait();
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        fake_processes_running(),
        0,
        "an agent survived the conductor"
    );
    let dir_s = dir.to_string_lossy().to_string();
    let rec = conductor(&f, &["reconcile", &dir_s]).output().unwrap();
    assert!(
        rec.status.success(),
        "reconcile: {}",
        String::from_utf8_lossy(&rec.stdout)
    );
    let mut resumed = conductor(&f, &["resume", &dir_s, "--canary-file", &canary_s])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = resumed.stdin.take().unwrap();
        stdin.write_all(b"yes\nyes\n").unwrap();
    }
    let out = resumed.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "resume: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let ev = events(&dir);
    assert!(
        ev.contains("\"interrupted\"") && ev.contains("reconcile_confirmed"),
        "the log records the interruption and the confirmation"
    );
    assert!(cycle::verify_events(&dir.join("events.jsonl")).is_ok());
    no_live_lease_on(&f.repo);
}

#[test]
fn s8_a_crash_during_a_windows_invocation_resumes_to_success() {
    crash_then_resume(
        "s8-win",
        r#"{"claude:design_review": ["sleep", "pass"]}"#,
        None,
        "D1-design_review",
    );
}

#[test]
fn s8_a_crash_during_implement_in_wsl_resumes_to_success() {
    crash_then_resume(
        "s8-wsl",
        "{}",
        Some("sleep-implement"),
        "\"label\":\"implement\"",
    );
}

// ---------------------------------------------------------------- S5 drift, against the real nl-cycle

/// Fake implement (no model call), real `nl-cycle bundle` and `verify`. With the `drift-mid-bundle`
/// marker, a file is added after the conductor's pre-bundle check and before nl-cycle bundles.
const HYBRID_NL_CYCLE: &str = r#"#!/bin/bash
here="$(dirname "$0")"
real="$here/nl-cycle-real"
cmd=$1; shift
case "$cmd" in
  implement) brief=$1; shift; [ "$1" = --repo ] && repo=$2
             echo "implemented line" >> "$repo/README.md"
             echo "new feature" > "$repo/feature.txt"
             echo implemented;;
  bundle)    args=("$@"); repo=
             while [ $# -gt 0 ]; do case $1 in --repo) repo=$2; shift 2;; *) shift;; esac; done
             if [ -e "$here/drift-mid-bundle" ]; then echo late > "$repo/late.txt"; fi
             exec "$real" bundle "${args[@]}";;
  verify)    exec "$real" verify "$@";;
  *) exit 64;;
esac
"#;

fn hybrid(name: &str) -> Fixture {
    let f = fixture(name);
    let nl = f.root.join("tools").join("nl-cycle");
    std::fs::write(&nl, HYBRID_NL_CYCLE).unwrap();
    wsl_sh(r#"chmod +x "$1""#, &[&f.nl_cycle_wsl]);
    f
}

/// Answers yes, after first doing something to the repository: the drift a reviewer never saw.
struct TamperThenYes(Option<Box<dyn FnMut()>>);

impl Operator for TamperThenYes {
    fn ask(&mut self, _q: &str, _until: Instant, _park: &Path) -> Answer {
        if let Some(mut f) = self.0.take() {
            f();
        }
        Answer::Yes
    }
}

fn hybrid_go(f: &Fixture, tamper: Option<Box<dyn FnMut()>>) -> (Terminal, PathBuf) {
    std::fs::write(&f.script, "{}").unwrap();
    std::env::set_var("LC_FAKE_SCRIPT", &f.script);
    std::env::set_var("LC_FAKE_STATE", &f.state);
    std::env::set_var("LC_FAKE_CANARY", CANARY);
    let run = run_for(f, SwarmMode::Ask);
    let dir = run.base.join(&run.cycle_id);
    std::fs::create_dir_all(&run.base).unwrap();
    let t = driver::drive(&run, &mut TamperThenYes(tamper)).unwrap();
    (t, dir)
}

#[test]
fn s5_control_a_clean_cycle_bundles_and_verifies_with_the_real_nl_cycle() {
    let f = hybrid("s5h-control");
    let (t, dir) = hybrid_go(&f, None);
    assert_eq!(t, Terminal::BundleVerifiedAwaitingOperatorSign);
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("bundle").join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(
        m.get("archive_sha512").is_some(),
        "the bundle manifest is the real nl-cycle's"
    );
    let verify = std::fs::read_to_string(dir.join("bundle").join("verify-stdout.txt")).unwrap();
    assert!(verify.contains("nl-cycle verified manifest"), "{verify}");
    no_live_lease_on(&f.repo);
}

fn assert_drift_before_bundle(t: Terminal, dir: &Path) {
    assert_eq!(t, Terminal::ParkedDrift);
    let ev = events(dir);
    assert!(
        ev.contains("before bundle"),
        "the conductor's own pre-bundle check caught it"
    );
    assert!(
        !ev.contains("\"label\":\"bundle\""),
        "nl-cycle bundle was never launched"
    );
}

#[test]
fn s5_drift_content_changed_after_review() {
    let f = hybrid("s5h-content");
    let file = f.repo.join("feature.txt");
    let (t, dir) = hybrid_go(
        &f,
        Some(Box::new(move || {
            std::fs::write(&file, b"changed after review\n").unwrap()
        })),
    );
    assert_drift_before_bundle(t, &dir);
}

#[test]
fn s5_drift_path_added_after_review() {
    let f = hybrid("s5h-added");
    let file = f.repo.join("extra.txt");
    let (t, dir) = hybrid_go(
        &f,
        Some(Box::new(move || {
            std::fs::write(&file, b"added after review\n").unwrap()
        })),
    );
    assert_drift_before_bundle(t, &dir);
}

#[test]
fn s5_drift_path_removed_after_review() {
    let f = hybrid("s5h-removed");
    // Reverting README.md takes it out of the delta: a reviewed path is no longer in the change.
    let repo_wsl = wsl::to_wsl_path(&f.repo).unwrap();
    let (t, dir) = hybrid_go(
        &f,
        Some(Box::new(move || {
            wsl_sh(r#"cd "$1" && git checkout -q -- README.md"#, &[&repo_wsl])
        })),
    );
    assert_drift_before_bundle(t, &dir);
}

#[test]
fn s5_drift_path_added_mid_bundle_is_refused_by_nl_cycle_and_classified_as_drift() {
    let f = hybrid("s5h-midbundle");
    f.mode("drift-mid-bundle");
    let (t, dir) = hybrid_go(&f, None);
    assert_eq!(t, Terminal::ParkedDrift);
    let ev = events(&dir);
    assert!(
        ev.contains("\"label\":\"bundle\""),
        "nl-cycle bundle was launched"
    );
    assert!(
        ev.contains("\"backend_ok\":false") && ev.contains("\"drift_after\":true"),
        "the backend refused and drift was found"
    );
    let out = std::fs::read_to_string(dir.join("bundle").join("bundle-stdout.txt"))
        .unwrap_or_default()
        + &std::fs::read_to_string(dir.join("bundle").join("bundle-stderr.txt"))
            .unwrap_or_default();
    assert!(!out.is_empty(), "nl-cycle said why it refused");
    println!("nl-cycle refusal: {}", out.trim());
}

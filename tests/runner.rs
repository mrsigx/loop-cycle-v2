//! Runner tests with harmless local processes only (no model calls). The WSL tests are the
//! mechanism half of gate S8: a `setsid`-daemonized Linux descendant must not survive (a) the
//! Windows Job Object killing `wsl.exe` at the conductor's deadline, or (b) the Linux-side timeout.
//! Terminal close, conductor crash and `reconcile` are not covered here.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use loop_cycle::cycle::{self, CycleDir, CycleError};
use loop_cycle::proc::{self, Ending, Spec};
use loop_cycle::{scan, templates, wsl};

fn scratch(name: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let target_base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
    let p = target_base
        .join("test-scratch")
        .join(format!("{name}-{stamp}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn windows_processes_with(token: &str) -> usize {
    // Excludes this query's own process, whose command line contains the token too.
    let q = format!(
        "@(Get-CimInstance Win32_Process | Where-Object {{ $_.ProcessId -ne $PID -and $_.CommandLine -like '*{token}*' }}).Count"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &q])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

fn spec<'a>(
    dir: &'a Path,
    a: &'a [String],
    deadline: Duration,
    park: Option<&'a Path>,
) -> Spec<'a> {
    Spec {
        argv: a,
        cwd: dir,
        stdin: None,
        stdout: dir.join("out.txt"),
        stderr: dir.join("err.txt"),
        deadline,
        park_file: park,
    }
}

#[test]
fn a_grandchild_dies_when_its_parent_exits() {
    let dir = scratch("grandchild");
    let token = format!("lc-gc-{}", std::process::id());
    // The parent starts a detached grandchild and exits at once.
    let parent = format!(
        "Start-Process powershell -ArgumentList '-NoProfile','-Command','Start-Sleep 60 # {token}' -WindowStyle Hidden; Start-Sleep 2; exit 0"
    );
    let a = argv(&["powershell", "-NoProfile", "-Command", &parent]);
    let out = proc::run(&spec(&dir, &a, Duration::from_secs(30), None)).unwrap();
    assert!(matches!(out.ending, Ending::Exited(_)), "{:?}", out.ending);
    assert!(out.windows_tree_confirmed);
    assert!(
        out.total_processes >= 2,
        "the grandchild ran inside the job ({} processes)",
        out.total_processes
    );
    assert_eq!(windows_processes_with(&token), 0, "no grandchild survives");
    let shells = out
        .images
        .iter()
        .filter(|i| i.to_ascii_lowercase().ends_with("powershell.exe"))
        .count();
    assert!(
        shells >= 2,
        "Windows reported both processes: {:?}",
        out.images
    );
}

#[test]
fn even_a_short_lived_process_is_reported() {
    let dir = scratch("short");
    let a = argv(&["cmd.exe", "/c", "where.exe where"]);
    let out = proc::run(&spec(&dir, &a, Duration::from_secs(20), None)).unwrap();
    assert!(
        out.images
            .iter()
            .any(|i| i.to_ascii_lowercase().ends_with("where.exe")),
        "{:?}",
        out.images
    );
}

#[test]
fn the_deadline_ends_the_invocation() {
    let dir = scratch("deadline");
    let a = argv(&["powershell", "-NoProfile", "-Command", "Start-Sleep 30"]);
    let started = Instant::now();
    let out = proc::run(&spec(&dir, &a, Duration::from_secs(2), None)).unwrap();
    assert_eq!(out.ending, Ending::Deadline);
    assert!(out.windows_tree_confirmed);
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[test]
fn capture_returns_unconfirmed_when_an_external_process_keeps_the_pipe_open() {
    let dir = scratch("external-pipe-holder");
    let script = dir.join("duplicate-stdout.ps1");
    std::fs::write(
        &script,
        r#"param([int]$TargetPid)
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class PipeDuplicate {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetStdHandle(int number);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle,
        IntPtr targetProcess, out IntPtr targetHandle, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
$target = [PipeDuplicate]::OpenProcess(0x0040, $false, [uint32]$TargetPid)
if ($target -eq [IntPtr]::Zero) { throw "OpenProcess failed" }
$duplicate = [IntPtr]::Zero
$ok = [PipeDuplicate]::DuplicateHandle(
    [PipeDuplicate]::GetCurrentProcess(),
    [PipeDuplicate]::GetStdHandle(-11),
    $target,
    [ref]$duplicate,
    0,
    $true,
    2)
[PipeDuplicate]::CloseHandle($target) | Out-Null
if (-not $ok) { throw "DuplicateHandle failed" }
[Console]::Out.Write("synthetic-prefix")
[Console]::Out.Flush()
"#,
    )
    .unwrap();

    let mut holder = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Start-Sleep 12"])
        .spawn()
        .unwrap();
    let holder_pid = holder.id().to_string();
    let script_arg = script.to_string_lossy().into_owned();
    let a = vec![
        "powershell".to_string(),
        "-NoProfile".to_string(),
        "-ExecutionPolicy".to_string(),
        "Bypass".to_string(),
        "-File".to_string(),
        script_arg,
        holder_pid,
    ];
    let started = Instant::now();
    let result = proc::run_captured(&spec(&dir, &a, Duration::from_secs(20), None));
    let _ = holder.kill();
    let _ = holder.wait();

    let (out, stdout, _stderr) = result.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "capture waited for an out-of-job pipe holder"
    );
    assert!(!out.windows_tree_confirmed, "pipe EOF was not confirmed");
    assert_eq!(stdout, b"synthetic-prefix");
}

#[cfg(feature = "fakes")]
fn output_helper(args: &[&str]) -> Vec<String> {
    let mut command = vec![env!("CARGO_BIN_EXE_lc-output-helper").to_string()];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

#[cfg(feature = "fakes")]
#[test]
fn exactly_the_combined_capture_limit_followed_by_eof_is_complete() {
    let dir = scratch("capture-exact-limit");
    let half = (8 * 1024 * 1024).to_string();
    let a = output_helper(&["finite", &half, &half]);
    let (out, stdout, stderr) =
        proc::run_captured(&spec(&dir, &a, Duration::from_secs(20), None)).unwrap();
    let capture = out.capture.unwrap();

    assert_eq!(out.ending, Ending::Exited(0));
    assert_eq!(stdout.len() + stderr.len(), 16 * 1024 * 1024);
    assert_eq!(capture.limit_bytes, 16 * 1024 * 1024);
    assert_eq!(capture.captured_bytes, capture.limit_bytes);
    assert_eq!(capture.discarded_bytes_observed, 0);
    assert!(capture.discard_count_complete);
    assert!(capture.capture_complete);
    assert!(!capture.output_limit_exceeded);
}

#[cfg(feature = "fakes")]
#[test]
fn the_first_excess_byte_is_an_irreversible_output_limit_failure() {
    let dir = scratch("capture-limit-plus-one");
    let over = (16 * 1024 * 1024 + 1).to_string();
    let a = output_helper(&["finite", &over, "0"]);
    let (out, stdout, stderr) =
        proc::run_captured(&spec(&dir, &a, Duration::from_secs(20), None)).unwrap();
    let capture = out.capture.unwrap();

    assert_eq!(out.ending, Ending::OutputLimitExceeded);
    assert_eq!(stdout.len() + stderr.len(), 16 * 1024 * 1024);
    assert_eq!(capture.captured_bytes, capture.limit_bytes);
    assert!(capture.discarded_bytes_observed >= 1);
    assert!(capture.output_limit_exceeded);
    assert!(!capture.capture_complete);
    assert_eq!(capture.retained_digest_coverage, "captured-prefix");
}

#[cfg(feature = "fakes")]
#[test]
fn stdout_and_stderr_compete_for_one_shared_capture_budget() {
    let dir = scratch("capture-shared-budget");
    let ten_mib = (10 * 1024 * 1024).to_string();
    let a = output_helper(&["finite", &ten_mib, &ten_mib]);
    let (out, stdout, stderr) =
        proc::run_captured(&spec(&dir, &a, Duration::from_secs(20), None)).unwrap();
    let capture = out.capture.unwrap();

    assert_eq!(out.ending, Ending::OutputLimitExceeded);
    assert_eq!(stdout.len() + stderr.len(), 16 * 1024 * 1024);
    assert_eq!(capture.captured_bytes, 16 * 1024 * 1024);
    assert!(capture.discarded_bytes_observed > 0);
}

#[cfg(feature = "fakes")]
#[test]
fn endless_output_is_cancelled_and_cleanup_stays_bounded() {
    let dir = scratch("capture-endless");
    let a = output_helper(&["endless"]);
    let started = Instant::now();
    let (out, _, _) = proc::run_captured(&spec(&dir, &a, Duration::from_secs(30), None)).unwrap();

    assert_eq!(out.ending, Ending::OutputLimitExceeded);
    assert!(out.capture.unwrap().output_limit_exceeded);
    assert!(started.elapsed() < Duration::from_secs(8));
}

#[cfg(feature = "fakes")]
#[test]
fn overflow_preserves_a_concurrent_park_observation() {
    let dir = scratch("capture-overflow-park");
    let park = dir.join("PARK");
    let park_arg = park.to_string_lossy().into_owned();
    let a = output_helper(&["overflow-park", &park_arg]);
    let (out, _, _) =
        proc::run_captured(&spec(&dir, &a, Duration::from_secs(20), Some(&park))).unwrap();

    assert_eq!(out.ending, Ending::OutputLimitExceeded);
    assert!(out.park_observed);
    assert!(out.capture.unwrap().output_limit_exceeded);
}

#[cfg(feature = "fakes")]
#[test]
fn exit_zero_overflow_preserves_a_park_seen_at_the_exit_decision() {
    let dir = scratch("capture-overflow-exit-park");
    let park = dir.join("PARK");
    let park_arg = park.to_string_lossy().into_owned();
    let a = output_helper(&["overflow-exit-park", &park_arg]);
    let (out, _, _) =
        proc::run_captured(&spec(&dir, &a, Duration::from_secs(20), Some(&park))).unwrap();

    assert_eq!(out.ending, Ending::OutputLimitExceeded);
    assert!(out.park_observed);
    assert!(out.capture.unwrap().output_limit_exceeded);
}

#[cfg(feature = "fakes")]
#[test]
fn overflow_preserves_a_concurrent_deadline_observation() {
    let dir = scratch("capture-overflow-deadline");
    let a = output_helper(&["overflow-sleep"]);
    let (out, stdout, stderr) =
        proc::run_captured(&spec(&dir, &a, Duration::from_millis(50), None)).unwrap();

    assert_eq!(out.ending, Ending::OutputLimitExceeded);
    assert!(out.deadline_observed);
    assert_eq!(stdout.len() + stderr.len(), 16 * 1024 * 1024);
    assert!(out.capture.unwrap().output_limit_exceeded);
}

#[test]
fn a_park_request_ends_the_invocation() {
    let dir = scratch("park");
    let park = dir.join("PARK");
    let p2 = park.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(1));
        std::fs::write(p2, b"park").unwrap();
    });
    let a = argv(&["powershell", "-NoProfile", "-Command", "Start-Sleep 30"]);
    let out = proc::run(&spec(&dir, &a, Duration::from_secs(30), Some(&park))).unwrap();
    assert_eq!(out.ending, Ending::ParkRequested);
    assert!(out.windows_tree_confirmed);
}

#[test]
fn stdin_is_delivered_then_closed() {
    let dir = scratch("stdin");
    let a = argv(&["cmd.exe", "/c", "more"]);
    let mut s = spec(&dir, &a, Duration::from_secs(20), None);
    s.stdin = Some(b"hello from the conductor\r\n");
    let out = proc::run(&s).unwrap();
    assert!(matches!(out.ending, Ending::Exited(0)), "{:?}", out.ending);
    let text = std::fs::read_to_string(dir.join("out.txt")).unwrap();
    assert!(text.contains("hello from the conductor"));
}

const ESCAPER: &str = "setsid sh -c 'exec sleep 300' </dev/null >/dev/null 2>&1 & sleep 300";

fn wsl_case(name: &str, windows_deadline: u64, linux_deadline: u64) {
    let dir = scratch(name);
    let ns_file = dir.join("ns.txt");
    let inner = argv(&["/bin/sh", "-c", ESCAPER]);
    let a = wsl::wrap(&inner, &ns_file, Duration::from_secs(linux_deadline)).unwrap();
    let out = proc::run(&spec(&dir, &a, Duration::from_secs(windows_deadline), None)).unwrap();
    assert!(out.windows_tree_confirmed, "{name}: Windows tree");
    let ns = wsl::recorded_namespace(&ns_file)
        .unwrap_or_else(|| panic!("{name}: no namespace recorded"));
    assert!(
        wsl::confirm_empty(&ns, Duration::from_secs(15)).unwrap(),
        "{name}: a process survived in {ns}"
    );
}

#[test]
fn wsl_namespace_dies_when_windows_kills_wsl_exe() {
    wsl_case("wsl-windows-deadline", 5, 120);
}

#[test]
fn wsl_namespace_dies_at_the_linux_timeout() {
    wsl_case("wsl-linux-timeout", 60, 3);
}

#[test]
fn wsl_paths_convert_and_refuse_non_drive_paths() {
    assert_eq!(
        wsl::to_wsl_path(Path::new(r"C:\loop-cycles\x\ns.txt")).as_deref(),
        Some("/mnt/c/loop-cycles/x/ns.txt")
    );
    assert_eq!(
        wsl::to_wsl_path(Path::new(r"\\wsl.localhost\Ubuntu\home")),
        None
    );
    assert_eq!(wsl::to_wsl_path(Path::new("relative\\x")), None);
}

#[test]
fn s2_mask_blocks_synthetic_home_keys_and_namespace_bypasses() {
    let dir = scratch("s2-mask");
    let home = dir.join("synthetic-home");
    let canary = "LCSYNTH-ONLY-7f3a9c";
    for name in [".ssh", ".gnupg"] {
        let p = home.join(name);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("canary.txt"), canary).unwrap();
    }
    for name in [
        "synthetic-home/.codex/sessions",
        "synthetic-home/.claude/projects",
        "synthetic-home/.nl-cycle/logs",
        "other-stage",
        "quarantine",
    ] {
        let p = dir.join(name);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("canary.txt"), canary).unwrap();
    }
    let home_wsl = wsl::to_wsl_path(&home).unwrap();
    let root_wsl = wsl::to_wsl_path(&dir).unwrap();
    let ssh = format!("{home_wsl}/.ssh");
    let gnupg = format!("{home_wsl}/.gnupg");
    let win = home
        .join(".ssh")
        .join("canary.txt")
        .to_string_lossy()
        .into_owned();
    let script = r#"
        leak() { case "$1" in *"$2"*) echo LEAKED;; *) echo blocked;; esac; }
        ssh=$1; gnupg=$2; win=$3; canary=$4; root=$5
        readable() { if [ "$(cat "$1" 2>/dev/null)" = "$canary" ]; then echo readable; else echo blocked; fi; }
        echo "ssh-direct=$(leak "$(cat "$ssh/canary.txt" 2>&1)" "$canary")"
        echo "gnupg-direct=$(leak "$(cat "$gnupg/canary.txt" 2>&1)" "$canary")"
        umount "$ssh" >/dev/null 2>&1; echo "umount-exit=$?"
        umount -l "$ssh" >/dev/null 2>&1; echo "lazy-umount-exit=$?"
        mount -o remount,rw "$ssh" >/dev/null 2>&1; echo "remount-exit=$?"
        echo "proc-self=$(leak "$(cat "/proc/self/root$ssh/canary.txt" 2>&1)" "$canary")"
        echo "proc-one=$(leak "$(cat "/proc/1/root$ssh/canary.txt" 2>&1)" "$canary")"
        echo "nested-userns=$(leak "$(unshare -rm sh -c "umount $ssh 2>&1; cat $ssh/canary.txt" 2>&1)" "$canary")"
        echo "home-search=$(leak "$(grep -r "$canary" "$HOME" 2>/dev/null)" "$canary")"
        echo "windows-interop=$(leak "$(/mnt/c/Windows/System32/cmd.exe /c type "$win" 2>&1)" "$canary")"
        echo "codex-store=$(readable "$HOME/.codex/sessions/canary.txt")"
        echo "claude-store=$(readable "$HOME/.claude/projects/canary.txt")"
        echo "nl-cycle-store=$(readable "$HOME/.nl-cycle/logs/canary.txt")"
        echo "other-stage=$(readable "$root/other-stage/canary.txt")"
        echo "quarantine=$(readable "$root/quarantine/canary.txt")"
        grep CapEff /proc/self/status
    "#;
    let inner = vec![
        "/bin/sh".into(),
        "-c".into(),
        script.into(),
        "probe".into(),
        ssh,
        gnupg,
        win,
        canary.into(),
        root_wsl,
    ];
    let ns_file = dir.join("ns.txt");
    let mut a = wsl::wrap(&inner, &ns_file, Duration::from_secs(40)).unwrap();
    // Only the probe gets a synthetic HOME. Production uses the WSL account's real HOME.
    a.insert(5, "/usr/bin/env".into());
    a.insert(6, format!("HOME={home_wsl}"));
    let out = proc::run(&spec(&dir, &a, Duration::from_secs(45), None)).unwrap();
    assert!(
        matches!(out.ending, Ending::Exited(0)),
        "{:?}: {}",
        out.ending,
        std::fs::read_to_string(dir.join("err.txt")).unwrap()
    );
    let report = std::fs::read_to_string(dir.join("out.txt")).unwrap();
    assert!(
        !report.contains(canary),
        "the synthetic canary reached the report"
    );
    for name in [
        "ssh-direct",
        "gnupg-direct",
        "proc-self",
        "proc-one",
        "nested-userns",
        "windows-interop",
    ] {
        assert!(
            report.contains(&format!("{name}=blocked")),
            "{name}: {report}"
        );
    }
    assert!(
        report.contains("home-search=LEAKED"),
        "unmasked session stores remain readable: {report}"
    );
    for name in ["umount-exit", "lazy-umount-exit", "remount-exit"] {
        assert!(!report.contains(&format!("{name}=0")), "{name}: {report}");
    }
    for name in [
        "codex-store",
        "claude-store",
        "nl-cycle-store",
        "other-stage",
        "quarantine",
    ] {
        assert!(
            report.contains(&format!("{name}=readable")),
            "{name}: {report}"
        );
    }
    assert!(report.contains("CapEff:\t0000000000000000"), "{report}");
    assert!(wsl::confirm_empty(
        &wsl::recorded_namespace(&ns_file).unwrap(),
        Duration::from_secs(15)
    )
    .unwrap());
    assert_eq!(
        std::fs::read_to_string(home.join(".ssh/canary.txt")).unwrap(),
        canary
    );
}

#[test]
fn the_scan_finds_credentials_and_canaries_in_any_bytes() {
    let canary = "LCCANARY-7f3a9c".to_string();
    assert!(scan::scan(b"nothing here, AKIA alone is a word", &[]).is_empty());
    let hits = scan::scan(b"key = sk-ant-api03-ABCDEFGHIJKLMNOP", &[]);
    assert_eq!(hits.len(), 1);
    assert!(!scan::scan(b"-----BEGIN OPENSSH PRIVATE KEY-----\nxyz", &[]).is_empty());
    let mut binary = vec![0u8, 159, 146, 150];
    binary.extend_from_slice(canary.as_bytes());
    binary.push(0);
    let hits = scan::scan(&binary, std::slice::from_ref(&canary));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].what, "canary");
}

#[test]
fn s7_encoded_synthetic_secrets_are_detected_without_echoing_them() {
    let canary = "LCSYNTH-SECRET-7f3a9c".to_string();
    let cases: &[(&str, &[u8])] = &[
        ("base64", b"TENTWU5USC1TRUNSRVQtN2YzYTlj"),
        ("hex", b"4c4353594e54482d5345435245542d376633613963"),
        (
            "percent",
            b"%4c%43%53%59%4e%54%48%2d%53%45%43%52%45%54%2d%37%66%33%61%39%63",
        ),
        (
            "json escape",
            br#"\u004c\u0043\u0053\u0059\u004e\u0054\u0048\u002dSECRET-7f3a9c"#,
        ),
    ];
    for (label, bytes) in cases {
        let hits = scan::scan(bytes, std::slice::from_ref(&canary));
        assert!(!hits.is_empty(), "{label} bypassed S7");
        assert!(
            hits.iter().all(|h| !h.what.contains(&canary)),
            "{label} echoed a canary"
        );
    }
    let mut utf16 = Vec::new();
    for b in canary.bytes() {
        utf16.extend_from_slice(&[b, 0]);
    }
    assert!(
        !scan::scan(&utf16, &[canary]).is_empty(),
        "UTF-16LE bypassed S7"
    );
}

fn account() -> String {
    std::env::var("USERNAME").unwrap()
}

#[test]
fn the_cycle_folder_chains_events_and_detects_tampering() {
    let base = scratch("cycles");
    let mut c = CycleDir::create(&base, "lc-test-1", &account()).unwrap();
    c.write_state(&serde_json::json!({"phase": "design"}))
        .unwrap();
    c.event("start", serde_json::json!({"cfg": 1}), &[])
        .unwrap();
    c.event(
        "launch",
        serde_json::json!({"agent": "agy"}),
        &[&c.state_path()],
    )
    .unwrap();
    assert_eq!(cycle::verify_events(&c.events_path()).unwrap(), 2);

    std::fs::write(c.state_path(), b"{\"phase\":\"bundle\"}").unwrap();
    assert!(matches!(
        c.event("next", serde_json::json!({}), &[]),
        Err(CycleError::ControlChanged("state.json"))
    ));

    let acl = Command::new("icacls").arg(&c.root).output().unwrap();
    let acl = String::from_utf8_lossy(&acl.stdout);
    assert!(acl.contains(&account()), "{acl}");
    assert!(
        !acl.contains("BUILTIN\\Users") && !acl.contains("Authenticated Users"),
        "{acl}"
    );
}

#[test]
fn staging_refuses_sensitive_files_and_directories() {
    let base = scratch("stage");
    let mut c = CycleDir::create(&base, "lc-test-2", &account()).unwrap();
    let src = base.join("design.md");
    std::fs::write(&src, b"# design").unwrap();
    let env = base.join(".env");
    std::fs::write(&env, b"TOKEN=x").unwrap();
    let staged = c
        .stage("design-review-claude", &[(&src, "design.md")], "review it")
        .unwrap();
    assert!(staged.join("design.md").exists() && staged.join("prompt.md").exists());
    assert!(matches!(
        c.stage("x", &[(&env, "notes.txt")], "p"),
        Err(CycleError::Sensitive(_))
    ));
    assert!(matches!(
        c.stage("y", &[(&src, "auth.json")], "p"),
        Err(CycleError::Sensitive(_))
    ));
    assert!(matches!(
        c.stage("z", &[(&base, "dir")], "p"),
        Err(CycleError::NotAFile(_))
    ));
    assert!(matches!(
        c.stage("w", &[(&src, "../escape.md")], "p"),
        Err(CycleError::NotAFile(_))
    ));
}

#[test]
fn an_authors_artifact_is_its_reply_without_the_result_block() {
    let reply = "# Design\n\nDo X.\n\n```loop-cycle-author\n{\"a\":1}\n```\nTrailing note.\n";
    assert_eq!(
        templates::artifact_from_reply(reply),
        "# Design\n\nDo X.\n\nTrailing note.\n"
    );
}

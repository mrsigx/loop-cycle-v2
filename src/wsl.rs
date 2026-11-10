//! WSL containment (DESIGN.md §9). A WSL invocation runs as
//! `wsl.exe -e timeout --kill-after … unshare --map-current-user --pid --fork --kill-child
//! --mount-proc sh -c <record-ns-then-exec> …`, so every Linux descendant lives in one new PID
//! namespace. The namespace's init records the namespace's identity (`pid:[inode]`) in a side file
//! first. When the namespace's init dies, the kernel kills everything left in it, `setsid`
//! included. Termination is confirmed by scanning `/proc` for any process still in that namespace.
//!
//! Whether killing `wsl.exe` from Windows (the Job Object) brings the namespace down is what
//! admission gate S8 must show. Until it does, WSL work is unadmitted.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Shared by the production wrapper and the synthetic S2 mask probe. Every mount operation must
/// succeed before the child starts. Capabilities are removed before the untrusted command runs.
pub const WRAP: &str = r#"
set -eu
readlink /proc/self/ns/pid > "$1" || exit 97
shift
mount --make-rprivate / || exit 98
for d in "$HOME/.ssh" "$HOME/.gnupg"; do
    if [ -e "$d" ] || [ -L "$d" ]; then
        [ -d "$d" ] && [ ! -L "$d" ] || exit 98
        mount -t tmpfs -o ro,size=4k,mode=0500 lc-mask "$d" || exit 98
    fi
done
# WSL can invoke Windows PE files through this socket and read masked paths from Windows.
# Hide the socket in the private mount namespace; changing the env var alone is insufficient.
if [ -d /run/WSL ]; then
    mount -t tmpfs -o ro,size=4k,mode=0500 lc-mask /run/WSL || exit 98
fi
WSL_INTEROP=/run/WSL/disabled
export WSL_INTEROP
exec /usr/bin/setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- "$@"
"#;

/// `C:\a\b` → `/mnt/c/a/b`. Only drive paths are accepted; anything else is refused.
pub fn to_wsl_path(p: &Path) -> Option<String> {
    let s = p.to_str()?;
    let mut chars = s.chars();
    let drive = chars.next()?.to_ascii_lowercase();
    if !drive.is_ascii_alphabetic() || chars.next()? != ':' {
        return None;
    }
    let rest: String = chars.collect::<String>().replace('\\', "/");
    if !rest.starts_with('/') {
        return None;
    }
    Some(format!("/mnt/{drive}{rest}"))
}

/// The fixed wrapper argv around `inner` (a WSL argv). `ns_file` receives `pid:[inode]`.
pub fn wrap(inner: &[String], ns_file: &Path, deadline: Duration) -> Option<Vec<String>> {
    let ns = to_wsl_path(ns_file)?;
    let secs = deadline.as_secs().max(1);
    let mut argv: Vec<String> = ["wsl.exe", "-e", "/usr/bin/timeout", "--kill-after=5s"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    argv.push(format!("{secs}s"));
    for s in [
        "/usr/bin/unshare",
        "--map-current-user",
        "--keep-caps",
        "--mount",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount-proc",
        "/bin/sh",
        "-c",
        WRAP,
        "lc-wrap",
    ] {
        argv.push(s.to_string());
    }
    argv.push(ns);
    argv.extend(inner.iter().cloned());
    Some(argv)
}

/// Reads the namespace identity the wrapper recorded, e.g. `pid:[4026532311]`.
pub fn recorded_namespace(ns_file: &Path) -> Option<String> {
    let s = std::fs::read_to_string(ns_file).ok()?;
    let s = s.trim();
    let ok = s.starts_with("pid:[")
        && s.ends_with(']')
        && s[5..s.len() - 1].chars().all(|c| c.is_ascii_digit());
    ok.then(|| s.to_string())
}

/// Counts live Linux processes in namespace `ns` (`pid:[inode]`). `Ok(0)` confirms termination.
pub fn processes_in_namespace(ns: &str) -> std::io::Result<u32> {
    let script = r#"n=0; for f in /proc/[0-9]*/ns/pid; do [ "$(readlink "$f" 2>/dev/null)" = "$1" ] && n=$((n+1)); done; echo "$n""#;
    let out = Command::new("wsl.exe")
        .args(["-e", "/bin/sh", "-c", script, "lc-scan", ns])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "namespace scan failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|e| std::io::Error::other(format!("namespace scan output: {e}")))
}

/// Polls until the namespace is empty or `wait` runs out. `Ok(true)` confirms termination.
pub fn confirm_empty(ns: &str, wait: Duration) -> std::io::Result<bool> {
    let start = std::time::Instant::now();
    loop {
        if processes_in_namespace(ns)? == 0 {
            return Ok(true);
        }
        if start.elapsed() >= wait {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

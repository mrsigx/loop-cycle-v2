//! The cycle folder (DESIGN.md §7, §10, §11): `<base>\<cycle-id>\`, outside every target
//! repository, with its ACL set to the operator's account only. It holds the append-only,
//! hash-chained `events.jsonl`, `state.json`, the park-request file, the quarantine, and one
//! staging directory per model invocation. The conductor owns the control files and rehashes them
//! before every transition; a change it didn't make parks the cycle.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    Ok(sha256_hex(&fs::read(p)?))
}

/// UTC now as `YYYY-MM-DDTHH:MM:SS.mmmZ`, from the system clock (no crate).
pub fn utc_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Files never staged for a model, whatever the input list says (§11).
pub fn is_sensitive(p: &Path) -> bool {
    p.components().any(|c| {
        let n = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        n.starts_with(".env")
            || n == ".secrets"
            || n == "nlsecrets"
            || n == "auth.json"
            || n.starts_with("id_rsa")
            || n.starts_with("id_ed25519")
            || n.starts_with("credentials")
            || n.ends_with(".pem")
            || n.ends_with(".key")
            || n.ends_with(".kdbx")
            || n.ends_with(".seed")
            || n == ".gnupg"
            || n == ".ssh"
    })
}

#[derive(Debug)]
pub enum CycleError {
    Io(std::io::Error),
    Acl(String),
    Exists(PathBuf),
    Sensitive(PathBuf),
    NotAFile(PathBuf),
    ControlChanged(&'static str),
}

impl From<std::io::Error> for CycleError {
    fn from(e: std::io::Error) -> Self {
        CycleError::Io(e)
    }
}

pub struct CycleDir {
    pub root: PathBuf,
    pub id: String,
    seq: u64,
    last_line_sha: String,
    events_sha: String,
    state_sha: Option<String>,
    stages: u32,
}

impl CycleDir {
    /// Creates `<base>\<id>` (refusing an existing one) and restricts its ACL to `account`.
    pub fn create(base: &Path, id: &str, account: &str) -> Result<CycleDir, CycleError> {
        let root = base.join(id);
        if root.exists() {
            return Err(CycleError::Exists(root));
        }
        fs::create_dir_all(&root)?;
        let grant = format!("{account}:(OI)(CI)F");
        let out = Command::new("icacls")
            .arg(&root)
            .args(["/inheritance:r", "/grant:r", &grant])
            .output()?;
        if !out.status.success() {
            return Err(CycleError::Acl(
                String::from_utf8_lossy(&out.stdout).into_owned(),
            ));
        }
        for sub in ["stages", "quarantine"] {
            fs::create_dir(root.join(sub))?;
        }
        File::create(root.join("events.jsonl"))?;
        let empty = sha256_hex(b"");
        Ok(CycleDir {
            root,
            id: id.to_string(),
            seq: 0,
            last_line_sha: empty.clone(),
            events_sha: empty,
            state_sha: None,
            stages: 0,
        })
    }

    /// Reopens an existing cycle folder (for `reconcile`), after verifying its event chain.
    pub fn open(root: &Path) -> Result<CycleDir, CycleError> {
        let events = root.join("events.jsonl");
        let seq = verify_events(&events).map_err(|e| CycleError::Io(std::io::Error::other(e)))?;
        let text = fs::read_to_string(&events)?;
        let last = text
            .lines()
            .last()
            .map(|l| sha256_hex(l.as_bytes()))
            .unwrap_or_else(|| sha256_hex(b""));
        let state = root.join("state.json");
        let state_sha = if state.exists() {
            Some(sha256_file(&state)?)
        } else {
            None
        };
        let stages = fs::read_dir(root.join("stages"))?.count() as u32;
        Ok(CycleDir {
            root: root.to_path_buf(),
            id: root
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
            seq,
            last_line_sha: last,
            events_sha: sha256_file(&events)?,
            state_sha,
            stages,
        })
    }

    /// The number of events recorded so far.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn events_path(&self) -> PathBuf {
        self.root.join("events.jsonl")
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    /// The park-request file. Its existence ends the running invocation (§9).
    pub fn park_path(&self) -> PathBuf {
        self.root.join("PARK")
    }

    /// Fails if a control file differs from what the conductor last wrote (§7).
    pub fn check_control(&self) -> Result<(), CycleError> {
        if sha256_file(&self.events_path())? != self.events_sha {
            return Err(CycleError::ControlChanged("events.jsonl"));
        }
        match (&self.state_sha, self.state_path().exists()) {
            (None, false) => {}
            (Some(s), true) if sha256_file(&self.state_path())? == *s => {}
            _ => return Err(CycleError::ControlChanged("state.json")),
        }
        Ok(())
    }

    /// Appends one event, chained to the previous line by its SHA-256, and fsyncs. Files named in
    /// `files` are recorded with their digests at this moment.
    pub fn event(&mut self, kind: &str, data: Value, files: &[&Path]) -> Result<(), CycleError> {
        self.check_control()?;
        let mut pins = Vec::new();
        for f in files {
            pins.push(json!({"path": f.to_string_lossy(), "sha256": sha256_file(f)?}));
        }
        self.seq += 1;
        let line = json!({
            "seq": self.seq,
            "at_utc": utc_now(),
            "kind": kind,
            "prev_sha256": self.last_line_sha,
            "data": data,
            "files": pins,
        });
        let text = serde_json::to_string(&line).expect("serializable") + "\n";
        let mut f = OpenOptions::new().append(true).open(self.events_path())?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        self.last_line_sha = sha256_hex(text.trim_end_matches('\n').as_bytes());
        self.events_sha = sha256_file(&self.events_path())?;
        Ok(())
    }

    pub fn write_state(&mut self, state: &Value) -> Result<(), CycleError> {
        self.check_control()?;
        let tmp = self.root.join("state.json.tmp");
        let text = serde_json::to_string_pretty(state).expect("serializable") + "\n";
        {
            let mut f = File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.state_path())?;
        self.state_sha = Some(sha256_hex(text.as_bytes()));
        Ok(())
    }

    /// Stores bytes that hit the secret scan, outside the artifact chain. Never staged or forwarded.
    pub fn quarantine(&mut self, name: &str, bytes: &[u8]) -> Result<PathBuf, CycleError> {
        let p = self.root.join("quarantine").join(name);
        let mut f = OpenOptions::new().write(true).create_new(true).open(&p)?;
        f.write_all(bytes)?;
        Ok(p)
    }

    /// A fresh staging directory for one model invocation, holding only `inputs` (copied, each a
    /// regular file, none sensitive) and `prompt.md`.
    pub fn stage(
        &mut self,
        label: &str,
        inputs: &[(&Path, &str)],
        prompt: &str,
    ) -> Result<PathBuf, CycleError> {
        self.stages += 1;
        let dir = self
            .root
            .join("stages")
            .join(format!("{:02}-{label}", self.stages));
        fs::create_dir(&dir)?;
        for (src, name) in inputs {
            if is_sensitive(src) || is_sensitive(Path::new(name)) {
                return Err(CycleError::Sensitive(src.to_path_buf()));
            }
            let meta = fs::symlink_metadata(src)?;
            if !meta.is_file() {
                return Err(CycleError::NotAFile(src.to_path_buf()));
            }
            if Path::new(name).components().count() != 1 {
                return Err(CycleError::NotAFile(PathBuf::from(name)));
            }
            fs::copy(src, dir.join(name))?;
        }
        fs::write(dir.join("prompt.md"), prompt)?;
        Ok(dir)
    }
}

/// Re-reads `events.jsonl` and checks the hash chain line by line.
pub fn verify_events(path: &Path) -> Result<u64, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut prev = sha256_hex(b"");
    let mut n = 0;
    for (i, line) in text.lines().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        if v["prev_sha256"] != Value::String(prev.clone()) {
            return Err(format!("line {}: chain break", i + 1));
        }
        if v["seq"] != json!(i as u64 + 1) {
            return Err(format!("line {}: sequence break", i + 1));
        }
        prev = sha256_hex(line.as_bytes());
        n += 1;
    }
    Ok(n)
}

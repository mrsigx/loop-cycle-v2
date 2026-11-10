//! The review manifest (DESIGN.md §8), built by the conductor from Git itself, never from a model.
//! Git runs in WSL, so the manifest sees the repository the way nl-cycle does. Content digests are
//! read by the conductor from the Windows path of the same files.
//!
//! Renames, copies, symlinks, unmerged entries and paths with control characters are refused: the
//! nl-cycle bundle refuses them too (nl-cycle.md), so a cycle can't get past review with them.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::cycle::sha256_hex;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Entry {
    pub path: String,
    /// `add`, `modify` or `delete`.
    pub action: String,
    /// Git mode: `100644`, `100755`, or `000000` for a deletion.
    pub mode: String,
    /// Git blob id of the working-tree content; empty for a deletion.
    pub blob: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Manifest {
    pub schema: String,
    pub repo_wsl: String,
    pub branch: String,
    pub base_commit: String,
    pub brief_sha256: String,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Equality of what a bundle would contain: every path, action, mode, blob and digest.
    pub fn same_delta(&self, other: &Manifest) -> bool {
        self.repo_wsl == other.repo_wsl
            && self.base_commit == other.base_commit
            && self.entries == other.entries
    }

    pub fn paths(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.path.clone()).collect()
    }
}

#[derive(Debug)]
pub enum GitError {
    Io(std::io::Error),
    Command(String),
    Refused(String),
}

impl From<std::io::Error> for GitError {
    fn from(e: std::io::Error) -> Self {
        GitError::Io(e)
    }
}

fn wsl_sh(script: &str, args: &[&str]) -> Result<String, GitError> {
    let mut cmd = Command::new("wsl.exe");
    cmd.args(["-e", "/bin/bash", "-c", script, "lc-git"])
        .args(args);
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(GitError::Command(format!(
            "exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The repository's head commit, branch, Git common directory (WSL path) and whether the working
/// tree is clean.
pub struct RepoInfo {
    pub base_commit: String,
    pub branch: String,
    pub common_dir_wsl: String,
    pub clean: bool,
}

pub fn repo_info(repo_wsl: &str) -> Result<RepoInfo, GitError> {
    let script = r#"cd "$1" || exit 90
git rev-parse HEAD || exit 91
git rev-parse --abbrev-ref HEAD || exit 92
git rev-parse --path-format=absolute --git-common-dir || exit 93
if [ -z "$(git status --porcelain=v1 --untracked-files=all)" ]; then echo clean; else echo dirty; fi"#;
    let out = wsl_sh(script, &[repo_wsl])?;
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    if lines.len() != 4 {
        return Err(GitError::Command(format!("unexpected repo info: {out:?}")));
    }
    Ok(RepoInfo {
        base_commit: lines[0].to_string(),
        branch: lines[1].to_string(),
        common_dir_wsl: lines[2].to_string(),
        clean: lines[3] == "clean",
    })
}

/// `/mnt/c/a/b` → `C:\a\b`; anything outside `/mnt/<drive>` is refused.
pub fn to_windows_path(wsl: &str) -> Option<PathBuf> {
    let rest = wsl.strip_prefix("/mnt/")?;
    let mut parts = rest.splitn(2, '/');
    let drive = parts.next()?;
    if drive.len() != 1 || !drive.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let tail = parts.next().unwrap_or("").replace('/', "\\");
    Some(PathBuf::from(format!(
        "{}:\\{}",
        drive.to_ascii_uppercase(),
        tail
    )))
}

/// Builds the manifest of the working delta against HEAD.
pub fn manifest(repo_wsl: &str, repo_win: &Path, brief_sha256: &str) -> Result<Manifest, GitError> {
    let info = repo_info(repo_wsl)?;
    // One line per entry: status code, mode, blob id, path. -z keeps paths exact; a rename or copy
    // entry (R/C) is refused below. The mode is Git's own, the same view as the diff and nl-cycle:
    // on a /mnt drive every file looks executable to `test -x`, so the filesystem bit is used only
    // when Git itself tracks file modes (core.fileMode). Tracked files take the new mode from
    // `git diff --raw`; new files are 100644 unless Git tracks modes and the file is executable.
    let script = r#"cd "$1" || exit 90
filemode=$(git config --bool core.fileMode || echo true)
git status --porcelain=v1 -z --untracked-files=all | while IFS= read -r -d '' rec; do
  code=$(printf '%s' "$rec" | cut -c1-2)
  path=$(printf '%s' "$rec" | cut -c4-)
  case "$code" in R*|C*|?R|?C) printf 'REFUSE\t-\t-\t%s\n' "$path"; continue;; esac
  if [ -L "$path" ]; then printf 'SYMLINK\t-\t-\t%s\n' "$path"; continue; fi
  if [ -e "$path" ]; then
    if git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
      mode=$(git diff --raw HEAD -- "$path" | head -1 | cut -d' ' -f2)
      [ -n "$mode" ] || mode=$(git ls-files --stage -- "$path" | head -1 | cut -d' ' -f1)
    elif [ "$filemode" = true ] && [ -x "$path" ]; then
      mode=100755
    else
      mode=100644
    fi
    blob=$(git hash-object -- "$path")
  else
    mode=000000; blob=-
  fi
  printf '%s\t%s\t%s\t%s\n' "$code" "$mode" "$blob" "$path"
done"#;
    let out = wsl_sh(script, &[repo_wsl])?;
    let mut entries = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.splitn(4, '\t').collect();
        if f.len() != 4 {
            return Err(GitError::Command(format!(
                "unexpected status line {line:?}"
            )));
        }
        let (code, mode, blob, path) = (f[0], f[1], f[2], f[3]);
        if path.chars().any(|c| c.is_control()) {
            return Err(GitError::Refused(format!(
                "control character in path {path:?}"
            )));
        }
        match code {
            "REFUSE" => return Err(GitError::Refused(format!("rename or copy: {path}"))),
            "SYMLINK" => return Err(GitError::Refused(format!("symlink: {path}"))),
            c if c.contains('U') || c == "AA" || c == "DD" => {
                return Err(GitError::Refused(format!("unmerged: {path}")))
            }
            _ => {}
        }
        let action = if mode == "000000" {
            "delete"
        } else if code == "??" || code.starts_with('A') {
            "add"
        } else {
            "modify"
        };
        let (sha, bytes) = if action == "delete" {
            (String::new(), 0)
        } else {
            let win = repo_win.join(path.replace('/', "\\"));
            let data = std::fs::read(&win)?;
            (sha256_hex(&data), data.len() as u64)
        };
        entries.push(Entry {
            path: path.to_string(),
            action: action.into(),
            mode: mode.into(),
            blob: if blob == "-" {
                String::new()
            } else {
                blob.into()
            },
            sha256: sha,
            bytes,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Manifest {
        schema: "loop-cycle-review-manifest/1".into(),
        repo_wsl: repo_wsl.into(),
        branch: info.branch,
        base_commit: info.base_commit,
        brief_sha256: brief_sha256.into(),
        entries,
    })
}

/// The reviewer's diff: tracked changes against HEAD plus each untracked file as a new-file diff.
/// Read-only: the index is never touched.
pub fn review_diff(repo_wsl: &str) -> Result<String, GitError> {
    let script = r#"cd "$1" || exit 90
filemode=$(git config --bool core.fileMode || echo true)
git --no-pager diff --no-color HEAD --
git ls-files --others --exclude-standard -z | while IFS= read -r -d '' f; do
  if [ "$filemode" = false ]; then
    git --no-pager diff --no-color --no-index -- /dev/null "$f" | sed 's/^new file mode 100755$/new file mode 100644/'
  else
    git --no-pager diff --no-color --no-index -- /dev/null "$f"
  fi
done
exit 0"#;
    wsl_sh(script, &[repo_wsl])
}

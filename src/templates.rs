//! Fixed command templates (DESIGN.md §7): the only agent launches. Every argument comes from the
//! conductor's configuration or its own paths, never from artifact text. Each model invocation runs
//! with its staging directory as working directory and is told only to read `prompt.md` there.
//!
//! Every model runs read-only. Authors' artifacts are their replies with the result block removed,
//! so no model needs a write tool (a tightening of DESIGN.md §6's "output path"; see REPORT.md).
//! Which isolation flags each CLI actually honours is what gate S2 measures: a flag listed here
//! is a request, not yet a demonstrated control.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::Agent;

pub const INSTRUCTION: &str =
    "Read prompt.md in the current directory and follow it exactly. Use no tools other than reading files in this directory.";

/// Absolute paths of the three CLIs and nl-cycle, resolved once at start and recorded with the
/// gate results (§12: results bind CLI versions).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Tools {
    pub agy: PathBuf,
    pub claude: PathBuf,
    pub codex: PathBuf,
    /// The WSL path of the installed nl-cycle launcher.
    pub nl_cycle_wsl: String,
    /// The Codex model for review and feasibility calls, pinned (never a moving `-latest` alias), so
    /// gate results bind it. The implementer's model is nl-cycle's own pin.
    pub codex_model: String,
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// A model invocation's argv. Every reply is captured from stdout before it reaches a stage file.
pub fn model_argv(
    tools: &Tools,
    agent: Agent,
    stage: &Path,
    _reply: &Path,
    deadline: Duration,
) -> Vec<String> {
    match agent {
        Agent::Agy => vec![
            s(&tools.agy),
            "-p".into(),
            INSTRUCTION.into(),
            "--mode".into(),
            "plan".into(),
            "--sandbox".into(),
            "--disable-slash-commands".into(),
            "--print-timeout".into(),
            format!("{}s", deadline.as_secs().max(1)),
            "--output-format".into(),
            "text".into(),
        ],
        Agent::Claude => vec![
            s(&tools.claude),
            "-p".into(),
            INSTRUCTION.into(),
            "--output-format".into(),
            "text".into(),
            "--tools".into(),
            "Read,Grep,Glob".into(),
            "--permission-mode".into(),
            "default".into(),
            "--setting-sources".into(),
            "".into(),
            "--strict-mcp-config".into(),
            "--no-session-persistence".into(),
        ],
        Agent::Codex => vec![
            s(&tools.codex),
            "exec".into(),
            "--ignore-user-config".into(),
            "--ephemeral".into(),
            "-m".into(),
            tools.codex_model.clone(),
            "-s".into(),
            "read-only".into(),
            "--skip-git-repo-check".into(),
            "-C".into(),
            s(stage),
            INSTRUCTION.into(),
        ],
    }
}

/// The implementer's inner WSL argv (to be wrapped by `wsl::wrap`): nl-cycle implement, which
/// launches its own Codex child inside the namespace.
pub fn implement_inner(tools: &Tools, brief_wsl: &str, repo_wsl: &str) -> Vec<String> {
    vec![
        tools.nl_cycle_wsl.clone(),
        "implement".into(),
        brief_wsl.into(),
        "--repo".into(),
        repo_wsl.into(),
    ]
}

/// Removes the result block from an author's reply, leaving the artifact text.
pub fn artifact_from_reply(reply: &str) -> String {
    let mut out = Vec::new();
    let mut skipping = false;
    for line in reply.lines() {
        let t = line.trim();
        if !skipping && t.starts_with("```loop-cycle-") {
            skipping = true;
            continue;
        }
        if skipping {
            if t == "```" {
                skipping = false;
            }
            continue;
        }
        out.push(line);
    }
    out.join("\n").trim().to_string() + "\n"
}

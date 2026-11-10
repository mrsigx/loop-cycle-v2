//! `loop-cycle` v2 conductor: pure result contracts, foreground cycle state machine, contained
//! Windows/WSL process launches, fail-closed 16 MiB stream capture, and pre-stage secret quarantine.
//! Real-repository runs remain gated behind explicit scratch-root admission until S1–S9 pass.

pub mod budget;
pub mod contract;
pub mod cycle;
pub mod driver;
pub mod git;
pub mod machine;
pub mod proc;
pub mod protocol;
pub mod provider;
pub mod scan;
pub mod templates;
pub mod wsl;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Agent {
    Agy,
    Claude,
    Codex,
}

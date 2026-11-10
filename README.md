# loop-cycle

`loop-cycle` is an operator-started, foreground Rust conductor for multi-agent software design, review, and implementation workflows on Windows + WSL2. It treats every model invocation and subprocess tree as an **untrusted execution boundary**: no agent may grade its own artifact, no model is granted write tools during authoring or review, truncated outputs fail closed rather than entering downstream parsers, and every child process tree must be provably dead before the state machine advances or resumes.

It runs strictly in the foreground with zero background daemons, watchers, or self-firing hooks, and terminates at `BundleVerifiedAwaitingOperatorSign`—never committing, signing, or pushing on the operator's behalf.

---

## Core Control & Containment Mechanisms

### 1. Separation of Duties & Strict Reply Contracts (`src/contract.rs`, `src/machine.rs`)
- **Non-Self-Review (`ContractError::SelfReview`):** Every artifact is reviewed by distinct agent lanes; attempting to route an author's artifact back to the same agent for review is rejected by the contract layer (`tests/s1_contracts.rs`, `tests/s3_routing.rs`).
- **Fail-Closed Envelope Parsing:** Model replies are parsed from stdout in memory before any stage file is written. Replies must contain **exactly one** `loop-cycle-author` or `loop-cycle-verdict` fenced JSON block, parsed through a custom `NoDuplicateKeys` visitor + `#[serde(deny_unknown_fields)]`, echoing the exact `cycle_id`, `phase`, `invocation_id`, and `SHA-256` input/artifact digest injected by the conductor. Nothing defaults to `pass`.

### 2. Win32 Job Object Containment & 16 MiB Fail-Closed Capture (`src/proc.rs`)
- **Zero-Escape Process Trees:** Windows invocations spawn with `CREATE_SUSPENDED | CREATE_NO_WINDOW`, attach to a dedicated `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Job Object monitored via an I/O completion port (`JOB_OBJECT_MSG_NEW_PROCESS`) before `NtResumeProcess`, and tear down through `bounded_cleanup` (explicit `TerminateJobObject`, bounded `active_processes == 0` poll, handle close, and non-blocking `try_wait()` root-child reap).
- **Bounded Fail-Closed Stream Capture (`docs/S1-OUTPUT-CAPTURE.md`):** Combined raw `stdout` + `stderr` share a single `16 MiB` (`16,777,216`-byte) budget (`MAX_CAPTURE_BYTES`). Complete runs require `<= 16,777,216` bytes and confirmed EOF on both pipes (`capture_complete: true`). A single excess byte forces `Ending::OutputLimitExceeded`—even if the child exits `0`—blocking truncated output from contract parsing or promotion while recording honest lower-bound discard metrics (`discarded_bytes_observed`, `discard_count_complete`). Inherited pipes held open outside the job are cancelled via `CancelSynchronousIo` so quarantine cannot stall.

### 3. WSL2 PID/Mount Namespace Isolation & Interop Masking (`src/wsl.rs`)
- **Namespace Teardown Verification:** WSL invocations execute under `unshare --map-current-user --keep-caps --mount --pid --fork --kill-child --mount-proc`, recording `pid:[inode]` before dropping all capabilities (`setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs`). Cleanup scans `/proc/[0-9]*/ns/pid` to confirm `live == 0` before `reconcile` or `resume` can proceed.
- **Credential & `/run/WSL` Socket Masking:** Inside the private mount namespace (`mount --make-rprivate /`), read-only `0500` `tmpfs` mounts mask `~/.ssh`, `~/.gnupg`, and **`/run/WSL`**—neutralizing the WSL Windows-PE interop socket (`cmd.exe` / `powershell.exe`) that could otherwise read masked host paths even when `WSL_INTEROP` is unset (`tests/runner.rs::s2_mask_blocks_synthetic_home_keys_and_namespace_bypasses`).

### 4. Pre-Stage Secret Quarantine, Drift Detection & Spend Accounting (`src/scan.rs`, `src/cycle.rs`, `src/budget.rs`)
- **Raw-Byte Secret & Canary Quarantine:** Output bytes (including binary, hex, percent-encoded, and base64/JWT payloads) are scanned before stage writes—even after timeouts, parks, or `OutputLimitExceeded`—transitioning on hit to `Terminal::ParkedSecret` and isolating raw bytes under `quarantine/`.
- **Hash-Chained Audit & Drift Guards:** `events.jsonl` hash-chains every transition and stage file digest; working-tree drift after diff review or mid-bundle is caught before operator handoff (`Terminal::ParkedDrift`). `BudgetJournal` enforces fail-closed pre-invocation spend reservations and tamper detection.

---

## Verified Scope & Explicit Boundaries

- **Platform:** Windows 10/11 (`x86_64-pc-windows-msvc`) with PowerShell 7 (`pwsh`) and WSL2 (`unshare`, `setpriv`, `timeout`, `git`, `python3`, `tar`).
- **Scratch-Root Admission Guard (`LOOP-CYCLE-SCRATCH-ROOT`):** By design (`src/driver.rs`), `loop-cycle run` refuses any repository outside an explicitly marked scratch root until live CLI admission gates (`S1`–`S9`) and residual-read policies are signed off for the operator's host environment.
- **Shared-Home Residual Reads:** As verified and asserted explicitly in `tests/runner.rs::s2_mask_blocks_synthetic_home_keys_and_namespace_bypasses`, masking `~/.ssh`, `~/.gnupg`, and `/run/WSL` blocks key theft, `/proc/1/root` traversal, nested `unshare -rm` remounts, and Windows PE interop escapes, **while leaving unmasked paths in the same Linux `$HOME` readable** unless run under a dedicated OS user or separate VM.

---

## Build & Test

Minimal Rust dependencies (`serde`, `serde_json`, `sha2`; raw Win32/ntdll FFI in `src/proc.rs` with no `windows-sys` crate).

```powershell
# Build release conductor binary
cargo build --release

# Run all 100 unit, contract, routing, containment, and scripted e2e tests (zero API calls)
cargo test --features fakes -- --test-threads=1
```

---

## Repository Layout

| Path | Role |
|---|---|
| `src/contract.rs` | Strict single-block JSON contract parser, `NoDuplicateKeys`, header digest binding, `SelfReview` guard |
| `src/proc.rs` | Win32 Job Object containment, completion-port process watch, `16 MiB` `OutputLimitExceeded` capture |
| `src/wsl.rs` | WSL2 user/mount/PID namespace wrapper, `/run/WSL` + key `tmpfs` masks, `/proc` namespace liveness scan |
| `src/scan.rs` | Raw-byte credential, JWT header, and cycle-canary scanner |
| `src/machine.rs` | Pure deterministic cycle state machine (`Full` and `Planning` modes) |
| `src/driver.rs` | Foreground cycle orchestrator, scratch admission guard, lease ownership, drift & bundle checks |
| `src/cycle.rs` | Cycle directory layout, control-file integrity checks, hash-chained `events.jsonl` |
| `src/budget.rs` | Hash-chained `BudgetJournal` pre-invocation spend reservation & settlement |
| `src/provider.rs` | Execution-profile preflight & provider usage-receipt verification |
| `scripts/lease.ps1` | Co-located atomic directory lease helper (`acquire` / `release` / `status`) |
| `scripts/nl-cycle-bundler.sh` | Reference Git working-tree bundler & SHA-512 manifest verifier |
| `docs/S1-OUTPUT-CAPTURE.md` | Specification for Revision 6 bounded fail-closed output capture |
| `tests/` | Contract (`s1_contracts.rs`), routing (`s3_routing.rs`), planning (`planning_protocol.rs`), runner/WSL (`runner.rs`), and end-to-end (`e2e.rs`) suites |

## Provenance

Architected and governed by Brandon Hacker at Null Limit Co., with multi-agent Rust implementation, adversarial containment testing, and release packaging executed under explicit contract gates across Claude Code, Codex, and Antigravity.

## License

Copyright (c) 2026 Null Limit Co. All rights reserved. Published for technical inspection and review; see [`LICENSE`](LICENSE).

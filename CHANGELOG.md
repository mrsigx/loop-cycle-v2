# Changelog

## 2.0.0 — 2026-11-10

First public release of the `loop-cycle` core conductor crate.

- Deterministic, non-recursive foreground state machine (`src/machine.rs`, `src/driver.rs`) enforcing cross-agent separation of duties (`ContractError::SelfReview`) across authoring, review, implementation, and bundle verification phases.
- Strict untrusted-reply contract parser (`src/contract.rs`) rejecting duplicate JSON keys (`NoDuplicateKeys`), unknown fields, multiple or stray fenced blocks, out-of-range scores, and mismatched `cycle_id` / `invocation_id` / `SHA-256` artifact headers.
- Contained Windows process execution (`src/proc.rs`) via `CREATE_SUSPENDED` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, I/O completion port process-creation tracking, non-blocking bounded teardown, `CancelSynchronousIo` pipe-stall recovery, and a shared `16 MiB` (`16,777,216`-byte) fail-closed stdout/stderr budget (`Ending::OutputLimitExceeded`; see `docs/S1-OUTPUT-CAPTURE.md`).
- Contained WSL2 execution (`src/wsl.rs`) via `unshare --map-current-user --keep-caps --mount --pid --fork --kill-child --mount-proc`, private mount propagation, `0500` read-only `tmpfs` masks over `~/.ssh`, `~/.gnupg`, and `/run/WSL`, `setpriv --no-new-privs` capability drop, and `/proc/[0-9]*/ns/pid` inode verification.
- Pre-stage raw-byte credential, JWT header, and canary scanner (`src/scan.rs`) with `ParkedSecret` quarantine, plus hash-chained `events.jsonl` (`src/cycle.rs`) and fail-closed `BudgetJournal` spend accounting (`src/budget.rs`).
- Portable PowerShell co-located directory lease helper (`scripts/lease.ps1`), reference Git working-tree bundler/verifier (`scripts/nl-cycle-bundler.sh`), and `100` offline unit, contract, routing, containment, and end-to-end tests (`17` library unit tests + `83` integration/containment/e2e tests).

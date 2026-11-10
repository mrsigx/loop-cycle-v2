# S1 Bounded Fail-Closed Output Capture Specification (Revision 6)

## Background & Prospective Contract Change

In earlier design revisions (through revision 5), admission gate S1 required complete, untruncated capture of child `stdout` and `stderr` without specifying a bounded memory ceiling, while the initial runner implementation capped each stream at `16 MiB + 1 byte`. Rather than treating truncated streams as compliant or allowing unbounded child output to exhaust host memory, Revision 6 prospectively adopts **bounded, fail-closed output capture**:

1. **Complete capture remains mandatory for every valid run.** Any invocation that completes within the shared byte budget and reaches confirmed EOF on both pipes is recorded as complete (`capture_complete: true`, `retained_digest_coverage: "complete-streams"`).
2. **Overflow is an irreversible fail-closed terminal state (`Ending::OutputLimitExceeded`).** The first byte beyond the shared `16 MiB` (`16,777,216`-byte) budget flips `overflow = true` and forces `Ending::OutputLimitExceeded`, even if the child later exits `0`, hits `Deadline`, or observes a `PARK` file.

---

## Core Invariants (`src/proc.rs`)

| Property | Invariant |
|---|---|
| **Shared Capture Ceiling** | `MAX_CAPTURE_BYTES = 16 * 1024 * 1024` (`16,777,216` raw bytes) shared across combined `stdout` and `stderr` per invocation via `CaptureBudget`. |
| **Exact Boundary Behavior** | `<= 16,777,216` combined bytes + confirmed EOF on both streams is eligible for contract parsing (`capture_complete: true`). `>= 16,777,217` bytes sets `output_limit_exceeded: true` and `capture_complete: false`. |
| **No Truncated Parsing or Promotion** | When `Ending::OutputLimitExceeded` occurs, retained bytes are never passed to `contract::parse_author` or `contract::parse_review`, never written as a valid stage artifact, and never promoted into review or bundle manifests. |
| **Honest Discarded-Byte Accounting** | `CaptureReport` records `limit_bytes`, `captured_bytes`, `discarded_bytes_observed`, and `discard_count_complete`. When bounded pipe shutdown cancels reads before pipe EOF (`discard_count_complete: false`), `discarded_bytes_observed` is explicitly treated as a lower bound rather than a total byte count. |
| **Escaped Pipe-Holder Defense** | If a descendant outside the Job Object (or a wedged kernel handle) keeps an inherited pipe open past `CAPTURE_EOF_GRACE` (`500 ms`), `finish_reader` issues Win32 `CancelSynchronousIo` (`CAPTURE_CANCEL_GRACE = 2 s`) and marks `windows_tree_confirmed = false` so quarantine cannot hang indefinitely. |
| **Pre-Stage Secret Quarantine on Overflow** | Even when an invocation ends in `OutputLimitExceeded`, `Deadline`, `ParkRequested`, or unconfirmed cleanup, the retained prefix (`<= 16 MiB`) is scanned by `scan::scan` before any stage write; any credential or canary match transitions the cycle to `Terminal::ParkedSecret` and isolates the bytes under `quarantine/`. |

//! A scripted stand-in for agy, Claude and Codex, for the no-cost end-to-end tests only (built with
//! `--features fakes`). It reads `prompt.md` in its working directory, takes the header the
//! conductor wrote, and replies as the script in `LC_FAKE_SCRIPT` says for this agent and phase:
//! `{"<agent>:<phase>": ["pass" | "revise" | "block" | "low" | "garbage" | "secret" | "exit1" |
//! "cx5" | "disagree" | "sleep" | "stderr-secret", ...]}`, one entry per call in order, the last entry repeating. Call counts
//! live in `LC_FAKE_STATE`. With no entry, an author writes complexity 2 at 0.9 and a reviewer
//! passes at 0.9.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ABC[((n >> 18) & 63) as usize] as char);
        out.push(ABC[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ABC[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ABC[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let agent = if args.iter().any(|a| a == "exec") {
        "codex"
    } else if args.iter().any(|a| a == "--mode") {
        "agy"
    } else {
        "claude"
    };
    let reply_file = args
        .iter()
        .position(|a| a == "-o")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let prompt = std::fs::read_to_string("prompt.md").expect("prompt.md in the working directory");
    let field = |k: &str| {
        prompt
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}: ")))
            .map(str::trim)
            .unwrap_or_default()
            .to_string()
    };
    let (cycle, phase, inv, digest, role) = (
        field("cycle_id"),
        field("phase"),
        field("invocation_id"),
        field("digest"),
        field("role"),
    );
    let key = format!("{agent}:{phase}");

    let script: HashMap<String, Vec<String>> = std::env::var("LC_FAKE_SCRIPT")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let state = std::env::var("LC_FAKE_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let counter = state.join(format!("{}.count", key.replace(':', "_")));
    let n: usize = std::fs::read_to_string(&counter)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let _ = std::fs::write(&counter, (n + 1).to_string());
    let action = script
        .get(&key)
        .and_then(|v| v.get(n).or_else(|| v.last()))
        .cloned()
        .unwrap_or_else(|| "default".into());

    if action == "sleep" {
        // Long enough to be caught mid-step by a crash test; the next call follows the script on.
        std::thread::sleep(std::time::Duration::from_secs(120));
    }
    if action == "stderr-secret-sleep" {
        eprintln!(
            "debug: {}",
            std::env::var("LC_FAKE_CANARY").unwrap_or_default()
        );
        std::thread::sleep(std::time::Duration::from_secs(120));
    }
    if action == "stdout-secret-sleep" {
        println!(
            "debug: {}",
            std::env::var("LC_FAKE_CANARY").unwrap_or_default()
        );
        std::io::stdout().flush().expect("flush synthetic output");
        std::thread::sleep(std::time::Duration::from_secs(120));
    }
    if action == "stderr-secret" {
        eprintln!(
            "debug: {}",
            std::env::var("LC_FAKE_CANARY").unwrap_or_default()
        );
    }
    if action == "stderr-secret-exit1" {
        eprintln!(
            "debug: {}",
            std::env::var("LC_FAKE_CANARY").unwrap_or_default()
        );
        std::process::exit(1);
    }
    if action == "stderr-secret-base64" {
        eprintln!(
            "debug: {}",
            base64(
                std::env::var("LC_FAKE_CANARY")
                    .unwrap_or_default()
                    .as_bytes()
            )
        );
    }
    if action == "output-limit" {
        let chunk = vec![b'X'; 64 * 1024];
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "debug: {}",
            std::env::var("LC_FAKE_CANARY").unwrap_or_default()
        )
        .expect("write synthetic canary");
        stdout.flush().expect("flush synthetic canary");
        for _ in 0..=256 {
            stdout.write_all(&chunk).expect("write synthetic overflow");
        }
        stdout.flush().expect("flush synthetic overflow");
    }
    let body = match action.as_str() {
        "exit1" => std::process::exit(1),
        "garbage" => "I think it looks fine overall.\n".to_string(),
        "secret" => format!(
            "Found this: {}\n",
            std::env::var("LC_FAKE_CANARY").unwrap_or_default()
        ),
        "secret-base64" => format!(
            "Found this: {}\n",
            base64(
                std::env::var("LC_FAKE_CANARY")
                    .unwrap_or_default()
                    .as_bytes()
            )
        ),
        _ if role == "author" => {
            let (cx, sc) = match action.as_str() {
                "cx5" => (5, 0.9),
                "disagree" => (2, 0.99),
                _ => (2, 0.9),
            };
            format!(
                "# {phase} by fake {agent}\n\nA design for the task.\n\n```loop-cycle-author\n{{\"schema\":\"loop-cycle-author/1\",\"cycle_id\":\"{cycle}\",\"phase\":\"{phase}\",\"invocation_id\":\"{inv}\",\"input_sha256\":\"{digest}\",\"complexity\":{cx},\"self_certainty\":{sc}}}\n```\n"
            )
        }
        _ => {
            let (verdict, certainty, cx) = match action.as_str() {
                "revise" => ("revise", 0.9, 2),
                "block" => ("block", 0.9, 2),
                "low" => ("pass", 0.5, 2),
                "cx5" => ("pass", 0.9, 5),
                "disagree" => ("pass", 0.4, 2),
                _ => ("pass", 0.9, 2),
            };
            format!(
                "Review by fake {agent}.\n\n```loop-cycle-verdict\n{{\"schema\":\"loop-cycle-verdict/1\",\"cycle_id\":\"{cycle}\",\"phase\":\"{phase}\",\"invocation_id\":\"{inv}\",\"artifact_sha256\":\"{digest}\",\"verdict\":\"{verdict}\",\"certainty\":{certainty},\"complexity\":{cx},\"reasons\":[\"scripted\"]}}\n```\n"
            )
        }
    };
    match reply_file {
        Some(p) => std::fs::write(p, body).expect("write reply"),
        None => print!("{body}"),
    }
}

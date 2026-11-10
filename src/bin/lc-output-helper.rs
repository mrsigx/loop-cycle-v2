//! Synthetic raw-output producer for no-cost capture tests only.

use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

const CHUNK: usize = 64 * 1024;

fn write_bytes(mut writer: impl Write, byte: u8, mut remaining: u64) {
    let chunk = vec![byte; CHUNK];
    while remaining != 0 {
        let n = remaining.min(CHUNK as u64) as usize;
        writer
            .write_all(&chunk[..n])
            .expect("write synthetic bytes");
        remaining -= n as u64;
    }
    writer.flush().expect("flush synthetic bytes");
}

fn finite(stdout_bytes: u64, stderr_bytes: u64) {
    let out = std::thread::spawn(move || write_bytes(io::stdout().lock(), b'O', stdout_bytes));
    let err = std::thread::spawn(move || write_bytes(io::stderr().lock(), b'E', stderr_bytes));
    out.join().unwrap();
    err.join().unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("finite") => finite(args[1].parse().unwrap(), args[2].parse().unwrap()),
        Some("endless") => loop {
            finite(CHUNK as u64, CHUNK as u64);
        },
        Some("overflow-sleep") => {
            write_bytes(io::stdout().lock(), b'O', 16 * 1024 * 1024 + 1);
            std::thread::sleep(Duration::from_secs(30));
        }
        Some("overflow-park") => {
            std::fs::write(Path::new(&args[1]), b"park").unwrap();
            write_bytes(io::stdout().lock(), b'O', 16 * 1024 * 1024 + 1);
            std::thread::sleep(Duration::from_secs(30));
        }
        Some("overflow-exit-park") => {
            std::fs::write(Path::new(&args[1]), b"park").unwrap();
            write_bytes(io::stdout().lock(), b'O', 16 * 1024 * 1024 + 1);
        }
        _ => panic!("usage: lc-output-helper finite <stdout> <stderr> | endless | overflow-sleep | overflow-park <path> | overflow-exit-park <path>"),
    }
}

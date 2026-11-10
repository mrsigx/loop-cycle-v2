//! The secret scan (DESIGN.md §11): credential-shaped strings and the cycle's canaries, over raw
//! bytes, so binary files are covered too. A hit quarantines the bytes and parks the cycle.

/// Prefixes of common credential formats. Deliberately narrow: a hit parks a cycle.
const PATTERNS: &[&str] = &[
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "untrusted comment: minisign encrypted secret key",
    "sk-ant-",
    "sk-proj-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hit {
    pub what: String,
    pub offset: usize,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn credential_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~' | b'+' | b'/')
}

fn labeled_value(bytes: &[u8], label: &[u8], min_len: usize, what: &str, hits: &mut Vec<Hit>) {
    for (at, window) in bytes.windows(label.len()).enumerate() {
        if !window.eq_ignore_ascii_case(label) {
            continue;
        }
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let mut i = at + label.len();
        if label == b"Bearer" && !matches!(bytes.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            continue;
        }
        if label != b"Bearer" && matches!(bytes.get(i), Some(b'\'' | b'"')) {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if label != b"Bearer" {
            if !matches!(bytes.get(i), Some(b':' | b'=')) {
                continue;
            }
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        if matches!(bytes.get(i), Some(b'\'' | b'"')) {
            i += 1;
        }
        let n = bytes[i..]
            .iter()
            .take_while(|b| credential_char(**b))
            .count();
        if n >= min_len {
            hits.push(Hit {
                what: what.into(),
                offset: at,
            });
        }
    }
}

fn jwt_header(segment: &[u8]) -> bool {
    if segment.len() > 4096 || segment.len() % 4 == 1 {
        return false;
    }
    let (mut acc, mut bits) = (0u32, 0u8);
    let mut decoded = Vec::with_capacity(segment.len() * 3 / 4);
    for &b in segment {
        acc = (acc << 6) | u32::from(b64_digit(b).expect("base64url segment"));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((acc >> bits) as u8);
        }
    }
    let body = decoded
        .iter()
        .copied()
        .skip_while(u8::is_ascii_whitespace)
        .collect::<Vec<_>>();
    body.first() == Some(&b'{') && body.windows(5).any(|w| w == b"\"alg\"")
}

fn scan_jwt(bytes: &[u8], hits: &mut Vec<Hit>) {
    for at in 0..bytes.len().saturating_sub(3) {
        if !bytes[at].is_ascii_alphanumeric() || (at > 0 && credential_char(bytes[at - 1])) {
            continue;
        }
        let mut i = at;
        let mut lengths = [0usize; 3];
        for (part, len) in lengths.iter_mut().enumerate() {
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'-'))
            {
                *len += 1;
                i += 1;
            }
            if part < 2 {
                if bytes.get(i) != Some(&b'.') {
                    break;
                }
                i += 1;
            }
        }
        let end_ok = i == bytes.len()
            || !credential_char(bytes[i])
            || (bytes[i] == b'.'
                && bytes.get(i + 1).is_none_or(|next| {
                    !next.is_ascii_alphanumeric() && !matches!(next, b'_' | b'-')
                }));
        if lengths[0] >= 8
            && lengths[1] >= 8
            && lengths[2] >= 16
            && end_ok
            && jwt_header(&bytes[at..at + lengths[0]])
        {
            hits.push(Hit {
                what: "jwt".into(),
                offset: at,
            });
        }
    }
}

/// Every pattern and canary found, by first offset. For the short prefixes (`AKIA`, `AIza`, …) a
/// hit needs at least 12 more credential-alphabet bytes after it, to keep ordinary words out.
fn scan_raw(bytes: &[u8], canaries: &[String]) -> Vec<Hit> {
    let mut hits = Vec::new();
    // These formats can hide a credential in compressed bytes. Without unpacking, park closed.
    for (magic, name) in [
        (&b"\x1f\x8b"[..], "gzip"),
        (&b"PK\x03\x04"[..], "zip"),
        (&b"\x28\xb5\x2f\xfd"[..], "zstd"),
        (&b"\xfd7zXZ\x00"[..], "xz"),
        (&b"BZh"[..], "bzip2"),
    ] {
        if bytes.starts_with(magic) {
            hits.push(Hit {
                what: format!("opaque-{name}"),
                offset: 0,
            });
        }
    }
    for p in PATTERNS {
        let pb = p.as_bytes();
        let mut start = 0;
        while let Some(i) = find(&bytes[start..], pb) {
            let at = start + i;
            let tail = &bytes[at + pb.len()..];
            let long_form = p.starts_with("-----") || p.starts_with("untrusted");
            let run = tail
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-')
                .count();
            if long_form || run >= 12 {
                hits.push(Hit {
                    what: p.to_string(),
                    offset: at,
                });
                break;
            }
            start = at + 1;
        }
    }
    labeled_value(bytes, b"Bearer", 20, "oauth-bearer", &mut hits);
    for label in [
        b"access_token".as_slice(),
        b"refresh_token",
        b"client_secret",
    ] {
        labeled_value(bytes, label, 16, "oauth-token", &mut hits);
    }
    scan_jwt(bytes, &mut hits);
    for c in canaries {
        if let Some(at) = find(bytes, c.as_bytes()) {
            // A hit label can be logged; never put the canary value in it.
            hits.push(Hit {
                what: "canary".into(),
                offset: at,
            });
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn b64_digit(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn add_view(hits: &mut Vec<Hit>, view: &[u8], canaries: &[String], kind: &str, at: usize) {
    for mut hit in scan_raw(view, canaries) {
        hit.what = format!("{kind}:{}", hit.what);
        hit.offset = at;
        hits.push(hit);
    }
}

fn scan_encoded_spans(bytes: &[u8], canaries: &[String], kind: &str, hits: &mut Vec<Hit>) {
    let mut i = 0;
    while i < bytes.len() {
        if b64_digit(bytes[i]).is_some() {
            let start = i;
            while i < bytes.len() && b64_digit(bytes[i]).is_some() {
                i += 1;
            }
            let span = &bytes[start..i];
            if span.len() >= 16 && span.len() % 4 != 1 {
                let (mut acc, mut bits) = (0u32, 0u8);
                let mut decoded = Vec::with_capacity(span.len() * 3 / 4);
                for &b in span {
                    acc = (acc << 6) | u32::from(b64_digit(b).expect("base64 span"));
                    bits += 6;
                    if bits >= 8 {
                        bits -= 8;
                        decoded.push((acc >> bits) as u8);
                    }
                }
                add_view(hits, &decoded, canaries, &format!("{kind}base64"), start);
            }
        } else {
            i += 1;
        }
    }

    let mut i = 0;
    while i < bytes.len() {
        if hex_digit(bytes[i]).is_some() {
            let start = i;
            while i < bytes.len() && hex_digit(bytes[i]).is_some() {
                i += 1;
            }
            let span = &bytes[start..i];
            if span.len() >= 24 {
                // Check both alignments so an adjacent hex digit cannot hide an encoded secret.
                for parity in 0..=1 {
                    let mut decoded = Vec::with_capacity((span.len() - parity) / 2);
                    for pair in span[parity..].chunks_exact(2) {
                        decoded.push(
                            hex_digit(pair[0]).expect("hex span") * 16
                                + hex_digit(pair[1]).expect("hex span"),
                        );
                    }
                    add_view(
                        hits,
                        &decoded,
                        canaries,
                        &format!("{kind}hex"),
                        start + parity,
                    );
                }
            }
        } else {
            i += 1;
        }
    }
}

fn decode_percent(bytes: &[u8]) -> Option<Vec<u8>> {
    let (mut out, mut i, mut changed) = (Vec::with_capacity(bytes.len()), 0, false);
    while i < bytes.len() {
        if i + 2 < bytes.len() && bytes[i] == b'%' {
            if let (Some(a), Some(b)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                out.push(a * 16 + b);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    changed.then_some(out)
}

fn decode_escapes(bytes: &[u8]) -> Option<Vec<u8>> {
    let (mut out, mut i, mut changed) = (Vec::with_capacity(bytes.len()), 0, false);
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let pair = if i + 5 < bytes.len()
                && bytes[i + 1] == b'u'
                && bytes[i + 2] == b'0'
                && bytes[i + 3] == b'0'
            {
                Some((i + 4, 6))
            } else if i + 3 < bytes.len() && bytes[i + 1] == b'x' {
                Some((i + 2, 4))
            } else {
                None
            };
            if let Some((at, advance)) = pair {
                if let (Some(a), Some(b)) = (hex_digit(bytes[at]), hex_digit(bytes[at + 1])) {
                    out.push(a * 16 + b);
                    i += advance;
                    changed = true;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    changed.then_some(out)
}

fn decode_utf16_ascii(bytes: &[u8], little: bool, parity: usize) -> Option<Vec<u8>> {
    if bytes.len() < 16 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut ascii_pairs = 0;
    for pair in bytes[parity..].chunks_exact(2) {
        let (lo, hi) = if little {
            (pair[0], pair[1])
        } else {
            (pair[1], pair[0])
        };
        if hi == 0 {
            out.push(lo);
            ascii_pairs += 1;
        } else {
            out.push(0);
        }
    }
    (ascii_pairs >= 8).then_some(out)
}

/// Finds raw secrets and common one-layer encodings before forwarding or bundling candidate bytes.
/// Oversized input parks closed. Arbitrary transforms and compression remain outside this tripwire.
pub fn scan(bytes: &[u8], canaries: &[String]) -> Vec<Hit> {
    if bytes.len() > MAX_SCAN_BYTES {
        return vec![Hit {
            what: "scan-size-limit".into(),
            offset: 0,
        }];
    }
    let mut hits = scan_raw(bytes, canaries);
    scan_encoded_spans(bytes, canaries, "", &mut hits);
    if let Some(view) = decode_percent(bytes) {
        add_view(&mut hits, &view, canaries, "percent", 0);
        scan_encoded_spans(&view, canaries, "percent:", &mut hits);
    }
    if let Some(view) = decode_escapes(bytes) {
        add_view(&mut hits, &view, canaries, "escape", 0);
        scan_encoded_spans(&view, canaries, "escape:", &mut hits);
    }
    for little in [true, false] {
        for parity in 0..=1 {
            if let Some(view) = decode_utf16_ascii(bytes, little, parity) {
                let kind = if little { "utf16le" } else { "utf16be" };
                add_view(&mut hits, &view, canaries, kind, parity);
                scan_encoded_spans(&view, canaries, &format!("{kind}:"), &mut hits);
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits
}

#[cfg(test)]
mod tests {
    use super::scan;

    #[test]
    fn oauth_and_jwt_shapes_are_detected_without_logging_values() {
        let cases = [
            (
                "Authorization: Bearer SYNTHETICabcdefghijklmnopqrstuv",
                "oauth-bearer",
            ),
            (
                "access_token=\"synthetic_access_token_0123456789\"",
                "oauth-token",
            ),
            (
                "{\"access_token\":\"synthetic_access_token_0123456789\"}",
                "oauth-token",
            ),
            (
                "REFRESH_TOKEN: synthetic_refresh_token_0123456789",
                "oauth-token",
            ),
            (
                "client_secret='synthetic_client_secret_0123456789'",
                "oauth-token",
            ),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.synthetic_signature_0123456789",
                "jwt",
            ),
            (
                "IHsiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJzeW50aGV0aWMifQ.synthetic_signature_0123456789.",
                "jwt",
            ),
        ];
        for (body, expected) in cases {
            let hits = scan(body.as_bytes(), &[]);
            assert!(
                hits.iter().any(|h| h.what == expected),
                "missing {expected}"
            );
            assert!(hits.iter().all(|h| !h.what.contains("synthetic")));
        }
    }

    #[test]
    fn bearer_prose_and_incomplete_jwt_are_not_credentials() {
        for body in [
            "Bearer authentication",
            "BearerSYNTHETICabcdefghijklmnopqrstuv",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.short",
        ] {
            assert!(
                scan(body.as_bytes(), &[]).is_empty(),
                "unexpected hit for {body}"
            );
        }
    }
}

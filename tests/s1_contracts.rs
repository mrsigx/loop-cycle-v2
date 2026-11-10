//! Admission gate S1, the parsing half (DESIGN.md §12): every malformed fixture is rejected and
//! the valid forms are accepted. The live-CLI half of S1 (each CLI emitting these blocks at
//! realistic sizes, with Windows→WSL quoting) needs real invocations and is not covered here.

use loop_cycle::contract::{parse_author, parse_review, ContractError, Header, Verdict};
use loop_cycle::Agent;

const DIGEST: &str = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34";

fn header() -> Header {
    Header {
        cycle_id: "lc-1".into(),
        phase: "design_review".into(),
        invocation_id: "inv-7".into(),
        digest: DIGEST.into(),
    }
}

fn verdict_json(fields: &str) -> String {
    format!("Review text.\n\n```loop-cycle-verdict\n{{{fields}}}\n```\n")
}

fn good_fields() -> String {
    format!(
        r#""schema":"loop-cycle-verdict/1","cycle_id":"lc-1","phase":"design_review","invocation_id":"inv-7","artifact_sha256":"{DIGEST}","verdict":"pass","certainty":0.9,"complexity":2,"reasons":["sound"]"#
    )
}

fn review(reply: &str) -> Result<loop_cycle::contract::Review, ContractError> {
    parse_review(reply, &header(), Agent::Claude, Agent::Agy)
}

#[test]
fn a_valid_review_is_accepted() {
    let r = review(&verdict_json(&good_fields())).expect("valid");
    assert_eq!(r.verdict, Verdict::Pass);
    assert_eq!(r.complexity, 2);
    assert_eq!(r.reviewer, Agent::Claude);
}

#[test]
fn an_unrelated_fenced_block_does_not_count() {
    let reply = format!(
        "```json\n{{\"x\":1}}\n```\n{}",
        verdict_json(&good_fields())
    );
    assert!(review(&reply).is_ok());
}

#[test]
fn malformed_reviews_are_each_rejected() {
    let g = good_fields();
    let cases: Vec<(&str, String)> = vec![
        ("no block", "Looks good to me. pass".to_string()),
        (
            "two blocks",
            format!("{}{}", verdict_json(&g), verdict_json(&g)),
        ),
        (
            "wrong tag",
            verdict_json(&g).replace("loop-cycle-verdict", "loop-cycle-author"),
        ),
        ("unterminated", format!("```loop-cycle-verdict\n{{{g}}}\n")),
        (
            "duplicate key",
            verdict_json(&format!("{g},\"verdict\":\"block\"")),
        ),
        (
            "unknown field",
            verdict_json(&format!("{g},\"note\":\"x\"")),
        ),
        (
            "missing field",
            verdict_json(&g.replace(r#","reasons":["sound"]"#, "")),
        ),
        (
            "wrong schema",
            verdict_json(&g.replace("loop-cycle-verdict/1", "loop-cycle-verdict/2")),
        ),
        ("NaN", verdict_json(&g.replace("0.9", "NaN"))),
        ("certainty above 1", verdict_json(&g.replace("0.9", "1.5"))),
        (
            "negative certainty",
            verdict_json(&g.replace("0.9", "-0.1")),
        ),
        (
            "complexity 0",
            verdict_json(&g.replace(r#""complexity":2"#, r#""complexity":0"#)),
        ),
        (
            "complexity 6",
            verdict_json(&g.replace(r#""complexity":2"#, r#""complexity":6"#)),
        ),
        (
            "non-integer complexity",
            verdict_json(&g.replace(r#""complexity":2"#, r#""complexity":2.5"#)),
        ),
        ("stale cycle id", verdict_json(&g.replace("lc-1", "lc-0"))),
        (
            "stale invocation",
            verdict_json(&g.replace("inv-7", "inv-6")),
        ),
        (
            "stale digest",
            verdict_json(&g.replace(DIGEST, &DIGEST.replace("ab", "ff"))),
        ),
        (
            "wrong phase",
            verdict_json(&g.replace("design_review", "brief_review")),
        ),
        (
            "author verdict word",
            verdict_json(&g.replace(r#""verdict":"pass""#, r#""verdict":"authored""#)),
        ),
        (
            "empty reasons",
            verdict_json(&g.replace(r#"["sound"]"#, "[]")),
        ),
        (
            "blank reason",
            verdict_json(&g.replace(r#"["sound"]"#, r#"["  "]"#)),
        ),
        (
            "not json",
            "```loop-cycle-verdict\nverdict: pass\n```\n".to_string(),
        ),
    ];
    for (name, reply) in cases {
        assert!(review(&reply).is_err(), "{name} was accepted");
    }
}

#[test]
fn a_reviewer_cannot_review_its_own_artifact() {
    let err = parse_review(
        &verdict_json(&good_fields()),
        &header(),
        Agent::Claude,
        Agent::Claude,
    )
    .unwrap_err();
    assert_eq!(err, ContractError::SelfReview(Agent::Claude));
}

fn author_reply(fields: &str) -> String {
    format!("Design written.\n```loop-cycle-author\n{{{fields}}}\n```")
}

fn author_fields() -> String {
    format!(
        r#""schema":"loop-cycle-author/1","cycle_id":"lc-1","phase":"design_review","invocation_id":"inv-7","input_sha256":"{DIGEST}","complexity":3,"self_certainty":0.7"#
    )
}

#[test]
fn author_results_are_strict_too() {
    let est = parse_author(&author_reply(&author_fields()), &header()).expect("valid");
    assert_eq!(est.complexity, 3);
    let a = author_fields();
    for (name, reply) in [
        (
            "reviewer tag",
            author_reply(&a).replace("loop-cycle-author", "loop-cycle-verdict"),
        ),
        (
            "verdict field",
            author_reply(&format!("{a},\"verdict\":\"pass\"")),
        ),
        (
            "stale input",
            author_reply(&a.replace(DIGEST, &DIGEST.replace("cd", "00"))),
        ),
        (
            "self certainty above 1",
            author_reply(&a.replace("0.7", "1.01")),
        ),
        (
            "duplicate key",
            author_reply(&format!("{a},\"complexity\":1")),
        ),
    ] {
        assert!(
            parse_author(&reply, &header()).is_err(),
            "{name} was accepted"
        );
    }
}

//! Admission gate S3 (DESIGN.md §12): a fixture for every row of §4 and every design outcome, each
//! asserting the exact sequence of next steps (expected states and, by exactness, no forbidden
//! advance). There is no "unroutable" state: an event with no transition parks as invalid.

use loop_cycle::contract::{AuthorEstimate, Review, Verdict};
use loop_cycle::machine::{
    Config, Counts, Cycle, Event, Next, Phase, ProtocolError, StartError, State, Step, SwarmMode,
    Terminal,
};
use loop_cycle::Agent;
use Agent::{Agy, Claude, Codex};

fn est(complexity: u8, self_certainty: f64) -> Event {
    Event::Authored(AuthorEstimate {
        complexity,
        self_certainty,
    })
}

fn rev(reviewer: Agent, verdict: Verdict, certainty: f64, complexity: u8) -> Event {
    Event::Reviewed(Review {
        reviewer,
        verdict,
        certainty,
        complexity,
        reasons: vec!["r".into()],
    })
}

fn pass(reviewer: Agent, cx: u8) -> Event {
    rev(reviewer, Verdict::Pass, 0.9, cx)
}

fn launch(agent: Agent, step: Step) -> Next {
    Next::Launch { agent, step }
}

fn cfg(swarm: SwarmMode) -> Config {
    Config {
        swarm,
        ..Config::default()
    }
}

fn go(c: &mut Cycle, e: Event) -> Next {
    c.on(e).expect("routable")
}

/// Runs from an accepted design to the end of a clean implementation and bundle.
fn finish_from_brief(c: &mut Cycle) -> Vec<Next> {
    vec![
        go(c, est(2, 0.9)),
        go(c, pass(Codex, 2)),
        go(c, Event::Implemented),
        go(c, pass(Claude, 2)),
        go(c, Event::AllowlistApproved(true)),
        go(
            c,
            Event::Bundled {
                drift_before: false,
                backend_ok: true,
                drift_after: false,
            },
        ),
    ]
}

const FINISH: [Next; 6] = [
    Next::Launch {
        agent: Codex,
        step: Step::BriefReview,
    },
    Next::Launch {
        agent: Codex,
        step: Step::Implement,
    },
    Next::Launch {
        agent: Claude,
        step: Step::DiffReview,
    },
    Next::AskAllowlist,
    Next::Bundle,
    Next::Stop(Terminal::BundleVerifiedAwaitingOperatorSign),
];

#[test]
fn direct_route_reaches_the_success_state() {
    let (mut c, n) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    assert_eq!(n, launch(Agy, Step::Design));
    assert_eq!(go(&mut c, est(2, 0.85)), launch(Claude, Step::DesignReview));
    assert_eq!(go(&mut c, pass(Claude, 2)), launch(Claude, Step::Brief));
    assert!(
        !c.reserve_held,
        "the reserve is released on entering BRIEF without swarm"
    );
    assert_eq!(finish_from_brief(&mut c), FINISH.to_vec());
    assert_eq!(c.used, Counts::new(1, 3, 2));
}

#[test]
fn author_complexity_three_adds_codex_feasibility() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(3, 0.8));
    assert_eq!(
        go(&mut c, pass(Claude, 3)),
        launch(Codex, Step::Feasibility)
    );
    assert_eq!(go(&mut c, pass(Codex, 3)), launch(Claude, Step::Brief));
}

#[test]
fn complexity_raised_mid_review_schedules_codex() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(2, 0.85));
    assert_eq!(
        go(&mut c, pass(Claude, 3)),
        launch(Codex, Step::Feasibility)
    );
}

#[test]
fn pass_below_threshold_and_high_certainty_revise_both_replan() {
    for review in [
        rev(Claude, Verdict::Pass, 0.79, 2),
        rev(Claude, Verdict::Revise, 0.95, 2),
    ] {
        let (mut c, _) = Cycle::start(cfg(SwarmMode::Off), None).unwrap();
        go(&mut c, est(2, 0.9));
        assert_eq!(go(&mut c, review), launch(Agy, Step::Design));
        assert_eq!(c.design_rev, 2);
    }
}

#[test]
fn block_parks_even_when_swarm_would_trigger() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Auto), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, rev(Claude, Verdict::Block, 0.9, 5));
    assert_eq!(
        go(&mut c, pass(Codex, 5)),
        Next::Stop(Terminal::ParkedBlocked)
    );
}

#[test]
fn complexity_five_on_d1_goes_to_swarm_and_through_to_brief() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    assert_eq!(
        go(&mut c, pass(Codex, 5)),
        Next::AskSwarmSpend,
        "pauses to ask, whatever the verdicts"
    );
    assert_eq!(c.state, State::Active(Phase::SwarmPending));
    assert_eq!(go(&mut c, Event::SwarmSpend(true)), Next::LaunchSwarm);
    assert_eq!(
        go(&mut c, Event::SwarmCaptured),
        launch(Claude, Step::SwarmMerge)
    );
    assert_eq!(
        go(&mut c, est(5, 0.8)),
        Next::AskAcceptMerge,
        "the operator always accepts the merge"
    );
    assert_eq!(
        go(&mut c, Event::MergeAccepted(true)),
        launch(Claude, Step::Brief)
    );
    assert!(c.swarm_used && !c.reserve_held);
}

#[test]
fn auto_swarm_skips_only_the_spending_question() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Auto), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    assert_eq!(go(&mut c, pass(Codex, 5)), Next::LaunchSwarm);
    go(&mut c, Event::SwarmCaptured);
    assert_eq!(go(&mut c, est(5, 0.8)), Next::AskAcceptMerge);
}

#[test]
fn disagreement_triggers_swarm_on_d1_only() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(2, 0.95));
    assert_eq!(
        go(&mut c, rev(Claude, Verdict::Pass, 0.5, 2)),
        Next::AskSwarmSpend
    );

    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(2, 0.9));
    go(&mut c, rev(Claude, Verdict::Revise, 0.9, 2));
    go(&mut c, est(2, 0.95));
    assert_eq!(
        go(&mut c, rev(Claude, Verdict::Pass, 0.5, 2)),
        launch(Agy, Step::Design),
        "D2 disagreement only replans"
    );
}

#[test]
fn swarm_off_treats_complexity_five_normally() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Off), None).unwrap();
    assert!(!c.reserve_held);
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    assert_eq!(go(&mut c, pass(Codex, 5)), launch(Claude, Step::Brief));
}

fn exhaust_planning(c: &mut Cycle) -> Next {
    let mut last = None;
    for _ in 0..4 {
        go(c, est(2, 0.9));
        last = Some(go(c, rev(Claude, Verdict::Revise, 0.9, 2)));
    }
    last.unwrap()
}

#[test]
fn exhausted_planning_enters_swarm_or_parks() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    assert_eq!(exhaust_planning(&mut c), Next::AskSwarmSpend);
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Off), None).unwrap();
    assert_eq!(exhaust_planning(&mut c), Next::Stop(Terminal::ParkedRounds));
}

#[test]
fn swarm_already_used_cannot_run_twice() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Auto), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    go(&mut c, pass(Codex, 5));
    go(&mut c, Event::SwarmCaptured);
    go(&mut c, est(5, 0.8));
    go(&mut c, Event::MergeAccepted(true));
    // After swarm, a complexity-5 brief review only informs: no second swarm, no replanning.
    go(&mut c, est(5, 0.9));
    assert_eq!(
        go(&mut c, rev(Codex, Verdict::Pass, 0.9, 5)),
        launch(Codex, Step::Implement)
    );
}

#[test]
fn operator_refusals_park() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    go(&mut c, pass(Codex, 5));
    assert_eq!(
        go(&mut c, Event::SwarmSpend(false)),
        Next::Stop(Terminal::ParkedRounds)
    );

    let (mut c, _) = Cycle::start(cfg(SwarmMode::Auto), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    go(&mut c, pass(Codex, 5));
    go(&mut c, Event::SwarmCaptured);
    go(&mut c, est(5, 0.8));
    assert_eq!(
        go(&mut c, Event::MergeAccepted(false)),
        Next::Stop(Terminal::ParkedRejected)
    );
}

fn to_brief(swarm: SwarmMode) -> Cycle {
    let (mut c, _) = Cycle::start(cfg(swarm), None).unwrap();
    go(&mut c, est(2, 0.9));
    go(&mut c, pass(Claude, 2));
    c
}

#[test]
fn brief_budget_exhaustion_parks() {
    let mut c = to_brief(SwarmMode::Ask);
    go(&mut c, est(2, 0.9));
    assert_eq!(
        go(&mut c, rev(Codex, Verdict::Revise, 0.9, 2)),
        launch(Claude, Step::Brief)
    );
    go(&mut c, est(2, 0.9));
    assert_eq!(
        go(&mut c, rev(Codex, Verdict::Pass, 0.5, 2)),
        Next::Stop(Terminal::ParkedRounds)
    );
}

#[test]
fn implementation_budget_exhaustion_parks_and_never_replans() {
    let mut c = to_brief(SwarmMode::Ask);
    go(&mut c, est(2, 0.9));
    go(&mut c, pass(Codex, 2));
    for round in 1..=3 {
        go(&mut c, Event::Implemented);
        let n = go(&mut c, rev(Claude, Verdict::Revise, 0.9, 5));
        if round < 3 {
            assert_eq!(
                n,
                launch(Codex, Step::Implement),
                "a diff revise goes back to Codex, not to design"
            );
        } else {
            assert_eq!(n, Next::Stop(Terminal::ParkedRounds));
        }
    }
}

#[test]
fn diff_block_and_allowlist_refusal_park() {
    let mut c = to_brief(SwarmMode::Ask);
    go(&mut c, est(2, 0.9));
    go(&mut c, pass(Codex, 2));
    go(&mut c, Event::Implemented);
    assert_eq!(
        go(&mut c, rev(Claude, Verdict::Block, 0.9, 2)),
        Next::Stop(Terminal::ParkedBlocked)
    );

    let mut c = to_brief(SwarmMode::Ask);
    go(&mut c, est(2, 0.9));
    go(&mut c, pass(Codex, 2));
    go(&mut c, Event::Implemented);
    go(&mut c, pass(Claude, 2));
    assert_eq!(
        go(&mut c, Event::AllowlistApproved(false)),
        Next::Stop(Terminal::ParkedRejected)
    );
}

#[test]
fn bundle_outcomes() {
    let cases = [
        ((true, true, false), Terminal::ParkedDrift),
        ((false, false, true), Terminal::ParkedDrift),
        ((false, false, false), Terminal::ParkedInvalid),
        ((false, true, true), Terminal::ParkedDrift),
        (
            (false, true, false),
            Terminal::BundleVerifiedAwaitingOperatorSign,
        ),
    ];
    for ((drift_before, backend_ok, drift_after), expected) in cases {
        let mut c = to_brief(SwarmMode::Ask);
        go(&mut c, est(2, 0.9));
        go(&mut c, pass(Codex, 2));
        go(&mut c, Event::Implemented);
        go(&mut c, pass(Claude, 2));
        go(&mut c, Event::AllowlistApproved(true));
        assert_eq!(
            go(
                &mut c,
                Event::Bundled {
                    drift_before,
                    backend_ok,
                    drift_after
                }
            ),
            Next::Stop(expected)
        );
    }
}

#[test]
fn a_round_that_cannot_fit_exhausts_planning_before_it_starts() {
    // agy cap 2 holds the swarm reserve (1) plus one round (1): round 2 can't fit.
    let tight = Config {
        swarm: SwarmMode::Ask,
        caps: Counts::new(2, 12, 8),
        ..Config::default()
    };
    let (mut c, _) = Cycle::start(tight.clone(), None).unwrap();
    go(&mut c, est(2, 0.9));
    assert_eq!(
        go(&mut c, rev(Claude, Verdict::Revise, 0.9, 2)),
        Next::AskSwarmSpend
    );
    assert_eq!(
        go(&mut c, Event::SwarmSpend(true)),
        Next::LaunchSwarm,
        "the reserve still covers the swarm"
    );

    // With no complete round yet, it is a limit, not exhaustion.
    let (_, n) = Cycle::start(
        Config {
            caps: Counts::new(1, 12, 8),
            ..tight
        },
        None,
    )
    .unwrap();
    assert_eq!(n, Next::Stop(Terminal::LimitReached));
}

#[test]
fn an_exact_fit_still_runs_the_reviews() {
    let exact = Config {
        swarm: SwarmMode::Off,
        caps: Counts::new(1, 1, 1),
        total_cap: 3,
        ..Config::default()
    };
    let (mut c, n) = Cycle::start(exact, None).unwrap();
    assert_eq!(n, launch(Agy, Step::Design));
    assert_eq!(
        go(&mut c, est(3, 0.9)),
        launch(Claude, Step::DesignReview),
        "agy at its cap does not stop the round"
    );
    assert_eq!(
        go(&mut c, pass(Claude, 3)),
        launch(Codex, Step::Feasibility)
    );
    assert_eq!(
        go(&mut c, pass(Codex, 3)),
        Next::Stop(Terminal::LimitReached),
        "the brief round can't fit"
    );
    assert_eq!(c.used, Counts::new(1, 1, 1));
}

#[test]
fn start_refuses_uncovered_reserve_and_zero_limits() {
    let small = Config {
        caps: Counts::new(1, 1, 1),
        total_cap: 3,
        ..Config::default()
    };
    assert_eq!(
        Cycle::start(small.clone(), None).unwrap_err(),
        StartError::SwarmReserveUncovered
    );
    assert!(Cycle::start(
        Config {
            swarm: SwarmMode::Off,
            ..small
        },
        None
    )
    .is_ok());
    let zero = Config {
        impl_rounds: 0,
        ..Config::default()
    };
    assert_eq!(
        Cycle::start(zero, None).unwrap_err(),
        StartError::NonPositiveLimit("impl rounds")
    );
}

#[test]
fn global_rules_apply_in_every_state_including_pauses() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(5, 0.9));
    go(&mut c, pass(Claude, 5));
    go(&mut c, pass(Codex, 5));
    assert_eq!(go(&mut c, Event::Cancel), Next::Stop(Terminal::Cancelled));

    for (event, expected) in [
        (Event::WallClock, Terminal::LimitReached),
        (Event::Invalid, Terminal::ParkedInvalid),
        (Event::Secret, Terminal::ParkedSecret),
        (Event::OutputLimitExceeded, Terminal::ParkedOutputLimit),
    ] {
        let mut c = to_brief(SwarmMode::Ask);
        go(&mut c, est(2, 0.9));
        go(&mut c, pass(Codex, 2));
        go(&mut c, Event::Implemented);
        go(&mut c, pass(Claude, 2));
        assert_eq!(
            go(&mut c, event),
            Next::Stop(expected),
            "during the allowlist pause"
        );
    }
}

#[test]
fn unexpected_events_park_as_invalid() {
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    assert!(matches!(
        c.on(Event::Implemented),
        Err(ProtocolError::Unexpected { .. })
    ));
    assert_eq!(c.state, State::Done(Terminal::ParkedInvalid));
    assert_eq!(
        c.on(Event::Cancel),
        Err(ProtocolError::AlreadyDone(Terminal::ParkedInvalid))
    );

    // A review from an agent that wasn't launched (here agy reviewing its own design).
    let (mut c, _) = Cycle::start(cfg(SwarmMode::Ask), None).unwrap();
    go(&mut c, est(2, 0.9));
    assert!(c.on(pass(Agy, 2)).is_err());
}

#[test]
fn imported_design_opens_at_its_review() {
    let imported = AuthorEstimate {
        complexity: 2,
        self_certainty: 0.9,
    };
    let (c, n) = Cycle::start(cfg(SwarmMode::Ask), Some(imported)).unwrap();
    assert_eq!(n, launch(Claude, Step::DesignReview));
    assert_eq!(
        c.used,
        Counts::new(1, 1, 0),
        "the import counts as one agy invocation"
    );
}

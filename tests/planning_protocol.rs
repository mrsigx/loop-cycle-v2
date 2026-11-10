use loop_cycle::contract::{AuthorEstimate, Review, Verdict};
use loop_cycle::machine::{Config, Event, Next, RunMode, Step, Terminal};
use loop_cycle::Agent;

fn passing_review(reviewer: Agent) -> Review {
    Review {
        reviewer,
        verdict: Verdict::Pass,
        certainty: 0.95,
        complexity: 2,
        reasons: vec!["bounded and testable".into()],
    }
}

#[test]
fn old_config_defaults_to_full_mode() {
    let value = serde_json::json!({
        "accept": 0.8,
        "disagreement": 0.4,
        "plan_rounds": 2,
        "brief_rounds": 2,
        "impl_rounds": 2,
        "swarm": "Off",
        "caps": {"agy": 4, "claude": 4, "codex": 4},
        "total_cap": 12
    });
    let cfg: Config = serde_json::from_value(value).unwrap();
    assert_eq!(cfg.run_mode, RunMode::Full);
}

#[test]
fn planning_mode_stops_before_brief_or_implementation() {
    let cfg = Config {
        run_mode: RunMode::Planning,
        swarm: loop_cycle::machine::SwarmMode::Off,
        ..Config::default()
    };
    let estimate = AuthorEstimate {
        complexity: 2,
        self_certainty: 0.95,
    };
    let (mut cycle, first) = loop_cycle::machine::Cycle::start(cfg, Some(estimate)).unwrap();
    assert_eq!(
        first,
        Next::Launch {
            agent: Agent::Claude,
            step: Step::DesignReview
        }
    );
    let next = cycle
        .on(Event::Reviewed(passing_review(Agent::Claude)))
        .unwrap();
    assert_eq!(next, Next::Stop(Terminal::PlanningComplete));
}

#[test]
fn capabilities_are_versioned_and_detachable() {
    let c = loop_cycle::protocol::capabilities();
    assert_eq!(c["schema"], "loop-cycle-capabilities/1");
    assert_eq!(c["protocol_version"], 1);
    assert_eq!(c["ui_contract"]["detachable"], true);
}

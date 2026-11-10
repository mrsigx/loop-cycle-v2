//! The cycle's state machine (DESIGN.md §4 and §10): pure, no I/O. The conductor feeds it one event
//! per finished invocation or operator answer, and it says what to do next. Invocation budget is
//! charged here, at the moment a launch is decided (the reservation written before the launch), so
//! whole-round reservation and the swarm reserve are checked against one ledger of counts.

use crate::contract::{AuthorEstimate, Review, Verdict};
use crate::Agent;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Design,
    DesignReview,
    SwarmPending,
    SwarmGenerate,
    SwarmMerge,
    OperatorAcceptMerge,
    Brief,
    BriefReview,
    Implement,
    DiffReview,
    AllowlistApproval,
    Bundle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Terminal {
    PlanningComplete,
    BundleVerifiedAwaitingOperatorSign,
    Cancelled,
    LimitReached,
    ParkedInvalid,
    ParkedBlocked,
    ParkedRounds,
    ParkedRejected,
    ParkedDrift,
    ParkedSecret,
    ParkedUnconfirmed,
    ParkedOutputLimit,
}

impl Terminal {
    pub const fn is_success(self) -> bool {
        matches!(
            self,
            Terminal::PlanningComplete | Terminal::BundleVerifiedAwaitingOperatorSign
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum State {
    Active(Phase),
    Done(Terminal),
}

/// What an invocation is for. Authors: Design, SwarmMerge, Brief. Reviewers: the rest but Implement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Step {
    Design,
    DesignReview,
    Feasibility,
    SwarmMerge,
    Brief,
    BriefReview,
    Implement,
    DiffReview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Next {
    Launch {
        agent: Agent,
        step: Step,
    },
    /// The three swarm candidates, in parallel, from one frozen snapshot (§5).
    LaunchSwarm,
    AskSwarmSpend,
    AskAcceptMerge,
    AskAllowlist,
    Bundle,
    Stop(Terminal),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Cancel,
    WallClock,
    Invalid,
    Secret,
    /// The combined stdout/stderr raw-byte budget was exceeded. This is irreversible for the
    /// invocation even when exit, timeout, park, or a scanner hit is also observed.
    OutputLimitExceeded,
    /// An invocation's processes could not be confirmed gone (§9).
    Unconfirmed,
    Authored(AuthorEstimate),
    Reviewed(Review),
    SwarmSpend(bool),
    SwarmCaptured,
    MergeAccepted(bool),
    Implemented,
    AllowlistApproved(bool),
    Bundled {
        drift_before: bool,
        backend_ok: bool,
        drift_after: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SwarmMode {
    Ask,
    Auto,
    Off,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    #[default]
    Full,
    Planning,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Counts {
    pub agy: u32,
    pub claude: u32,
    pub codex: u32,
}

impl Counts {
    pub const fn new(agy: u32, claude: u32, codex: u32) -> Self {
        Counts { agy, claude, codex }
    }
    pub fn total(&self) -> u32 {
        self.agy + self.claude + self.codex
    }
    fn bump(&mut self, a: Agent) {
        match a {
            Agent::Agy => self.agy += 1,
            Agent::Claude => self.claude += 1,
            Agent::Codex => self.codex += 1,
        }
    }
}

/// One swarm episode: three candidates and Claude's merge.
pub const SWARM_RESERVE: Counts = Counts::new(1, 2, 1);
/// An ordinary design round at its largest: agy designs, Claude reviews, Codex may be added.
pub const DESIGN_ROUND: Counts = Counts::new(1, 1, 1);
pub const BRIEF_ROUND: Counts = Counts::new(0, 1, 1);
pub const IMPL_ROUND: Counts = Counts::new(0, 1, 1);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub accept: f64,
    pub disagreement: f64,
    pub plan_rounds: u32,
    pub brief_rounds: u32,
    pub impl_rounds: u32,
    pub swarm: SwarmMode,
    pub caps: Counts,
    pub total_cap: u32,
    #[serde(default)]
    pub run_mode: RunMode,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            accept: 0.80,
            disagreement: 0.40,
            plan_rounds: 4,
            brief_rounds: 2,
            impl_rounds: 3,
            swarm: SwarmMode::Ask,
            caps: Counts::new(8, 12, 8),
            total_cap: 24,
            run_mode: RunMode::Full,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartError {
    /// Limits must be positive and finite (§10).
    NonPositiveLimit(&'static str),
    /// The hard limits can't cover one swarm episode and swarm isn't off (§10).
    SwarmReserveUncovered,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// An event that has no transition from the current state. The cycle parks as invalid.
    Unexpected {
        state: State,
        event: String,
    },
    AlreadyDone(Terminal),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Cycle {
    pub cfg: Config,
    pub state: State,
    pub used: Counts,
    pub reserve_held: bool,
    pub swarm_used: bool,
    pub design_rev: u32,
    pub complete_design_rounds: u32,
    pub brief_rounds_used: u32,
    pub impl_rounds_used: u32,
    estimate: Option<AuthorEstimate>,
    reviews: Vec<Review>,
    pending: Option<Agent>,
}

impl Cycle {
    /// Starts a cycle. With `imported`, agy's interactive design is D1 (counted as one agy
    /// invocation) and the cycle opens at its review; otherwise it launches agy for D1.
    pub fn start(
        cfg: Config,
        imported: Option<AuthorEstimate>,
    ) -> Result<(Cycle, Next), StartError> {
        for (name, v) in [
            ("agy cap", cfg.caps.agy),
            ("claude cap", cfg.caps.claude),
            ("codex cap", cfg.caps.codex),
            ("total cap", cfg.total_cap),
            ("plan rounds", cfg.plan_rounds),
            ("brief rounds", cfg.brief_rounds),
            ("impl rounds", cfg.impl_rounds),
        ] {
            if v == 0 {
                return Err(StartError::NonPositiveLimit(name));
            }
        }
        let reserve_held = cfg.swarm != SwarmMode::Off;
        let mut c = Cycle {
            cfg,
            state: State::Active(Phase::Design),
            used: Counts::default(),
            reserve_held,
            swarm_used: false,
            design_rev: 0,
            complete_design_rounds: 0,
            brief_rounds_used: 0,
            impl_rounds_used: 0,
            estimate: None,
            reviews: Vec::new(),
            pending: None,
        };
        if reserve_held && !c.covers(Counts::default(), true) {
            return Err(StartError::SwarmReserveUncovered);
        }
        let next = match imported {
            None => c.start_design_round(),
            Some(est) => {
                if !c.covers(DESIGN_ROUND, c.reserve_held) {
                    c.stop(Terminal::LimitReached)
                } else {
                    c.design_rev = 1;
                    c.used.bump(Agent::Agy);
                    c.authored_design(est)
                }
            }
        };
        Ok((c, next))
    }

    /// Whether `need`, on top of what is used (and the reserve if held), stays within every cap.
    fn covers(&self, need: Counts, with_reserve: bool) -> bool {
        let r = if with_reserve {
            SWARM_RESERVE
        } else {
            Counts::default()
        };
        let caps = self.cfg.caps;
        self.used.agy + need.agy + r.agy <= caps.agy
            && self.used.claude + need.claude + r.claude <= caps.claude
            && self.used.codex + need.codex + r.codex <= caps.codex
            && self.used.total() + need.total() + r.total() <= self.cfg.total_cap
    }

    fn stop(&mut self, t: Terminal) -> Next {
        self.state = State::Done(t);
        self.pending = None;
        Next::Stop(t)
    }

    fn enter(&mut self, p: Phase) {
        self.state = State::Active(p);
    }

    /// Rule 1a: a launch that would exceed a cap is never started.
    fn launch(&mut self, agent: Agent, step: Step) -> Next {
        let mut need = Counts::default();
        need.bump(agent);
        if !self.covers(need, false) {
            return self.stop(Terminal::LimitReached);
        }
        self.used.bump(agent);
        self.pending = Some(agent);
        Next::Launch { agent, step }
    }

    fn start_design_round(&mut self) -> Next {
        if self.design_rev >= self.cfg.plan_rounds || !self.covers(DESIGN_ROUND, self.reserve_held)
        {
            return if self.complete_design_rounds == 0 {
                self.stop(Terminal::LimitReached)
            } else {
                self.planning_exhausted()
            };
        }
        self.design_rev += 1;
        self.estimate = None;
        self.reviews.clear();
        self.enter(Phase::Design);
        self.launch(Agent::Agy, Step::Design)
    }

    fn authored_design(&mut self, est: AuthorEstimate) -> Next {
        self.estimate = Some(est);
        self.reviews.clear();
        self.enter(Phase::DesignReview);
        self.launch(Agent::Claude, Step::DesignReview)
    }

    fn effective_complexity(&self) -> u8 {
        let author = self.estimate.as_ref().map_or(1, |e| e.complexity);
        self.reviews
            .iter()
            .map(|r| r.complexity)
            .fold(author, u8::max)
    }

    fn swarm_eligible(&self) -> bool {
        self.cfg.swarm != SwarmMode::Off && !self.swarm_used && self.reserve_held
    }

    fn design_review_complete(&mut self) -> Next {
        if self.reviews.iter().any(|r| r.verdict == Verdict::Block) {
            return self.stop(Terminal::ParkedBlocked);
        }
        self.complete_design_rounds += 1;
        let min_cert = self.reviews.iter().map(|r| r.certainty).fold(1.0, f64::min);
        let self_cert = self
            .estimate
            .as_ref()
            .map_or(min_cert, |e| e.self_certainty);
        let disagree = (self_cert - min_cert).abs() >= self.cfg.disagreement;
        if self.design_rev == 1
            && self.swarm_eligible()
            && (self.effective_complexity() == 5 || disagree)
        {
            return self.swarm_pending();
        }
        let accepted =
            self.reviews.iter().all(|r| r.verdict == Verdict::Pass) && min_cert >= self.cfg.accept;
        if accepted {
            self.reserve_held = false;
            return self.accepted_plan();
        }
        self.start_design_round()
    }

    fn accepted_plan(&mut self) -> Next {
        match self.cfg.run_mode {
            RunMode::Planning => self.stop(Terminal::PlanningComplete),
            RunMode::Full => self.start_brief_round(),
        }
    }

    fn planning_exhausted(&mut self) -> Next {
        if self.swarm_eligible() {
            self.swarm_pending()
        } else {
            self.stop(Terminal::ParkedRounds)
        }
    }

    fn swarm_pending(&mut self) -> Next {
        self.enter(Phase::SwarmPending);
        self.pending = None;
        match self.cfg.swarm {
            SwarmMode::Auto => self.begin_swarm(),
            _ => Next::AskSwarmSpend,
        }
    }

    fn begin_swarm(&mut self) -> Next {
        // The reserve is released into the episode it was held for.
        self.reserve_held = false;
        self.swarm_used = true;
        if !self.covers(SWARM_RESERVE, false) {
            return self.stop(Terminal::LimitReached);
        }
        self.used.agy += 1;
        self.used.claude += 1;
        self.used.codex += 1;
        self.enter(Phase::SwarmGenerate);
        self.pending = None;
        Next::LaunchSwarm
    }

    fn start_brief_round(&mut self) -> Next {
        if self.brief_rounds_used >= self.cfg.brief_rounds {
            return self.stop(Terminal::ParkedRounds);
        }
        if !self.covers(BRIEF_ROUND, self.reserve_held) {
            return self.stop(Terminal::LimitReached);
        }
        self.brief_rounds_used += 1;
        self.enter(Phase::Brief);
        self.launch(Agent::Claude, Step::Brief)
    }

    pub fn start_impl_round(&mut self) -> Next {
        if self.impl_rounds_used >= self.cfg.impl_rounds {
            return self.stop(Terminal::ParkedRounds);
        }
        if !self.covers(IMPL_ROUND, self.reserve_held) {
            return self.stop(Terminal::LimitReached);
        }
        self.impl_rounds_used += 1;
        self.enter(Phase::Implement);
        self.launch(Agent::Codex, Step::Implement)
    }

    pub fn accept_imported_brief(&mut self) -> Next {
        if self.cfg.run_mode == RunMode::Planning {
            return self.stop(Terminal::PlanningComplete);
        }
        self.reserve_held = false;
        self.brief_rounds_used = 1;
        self.used.bump(Agent::Claude);
        self.used.bump(Agent::Codex);
        self.start_impl_round()
    }

    /// Counts a rerun of an interrupted invocation (`resume`): failed and uncertain invocations
    /// count (§10), so the rerun is charged again. A rerun that would exceed a cap stops the cycle.
    pub fn recharge(&mut self, agent: Agent) -> Option<Next> {
        let mut need = Counts::default();
        need.bump(agent);
        if !self.covers(need, false) {
            return Some(self.stop(Terminal::LimitReached));
        }
        self.used.bump(agent);
        None
    }

    fn accepted(&self, r: &Review) -> bool {
        r.verdict == Verdict::Pass && r.certainty >= self.cfg.accept
    }

    fn expect_reviewer(&self, r: &Review) -> bool {
        self.pending == Some(r.reviewer)
    }

    /// Applies one event. Global rules come first (§4 rules 1–3), and apply in every active state,
    /// operator pauses included. An event with no transition parks the cycle as invalid.
    pub fn on(&mut self, event: Event) -> Result<Next, ProtocolError> {
        let phase = match self.state {
            State::Done(t) => return Err(ProtocolError::AlreadyDone(t)),
            State::Active(p) => p,
        };
        let next = match (phase, event) {
            (_, Event::Cancel) => self.stop(Terminal::Cancelled),
            (_, Event::WallClock) => self.stop(Terminal::LimitReached),
            (_, Event::Invalid) => self.stop(Terminal::ParkedInvalid),
            (_, Event::Secret) => self.stop(Terminal::ParkedSecret),
            (_, Event::Unconfirmed) => self.stop(Terminal::ParkedUnconfirmed),
            (_, Event::OutputLimitExceeded) => self.stop(Terminal::ParkedOutputLimit),

            (Phase::Design, Event::Authored(est)) if self.pending == Some(Agent::Agy) => {
                self.authored_design(est)
            }
            (Phase::DesignReview, Event::Reviewed(r)) if self.expect_reviewer(&r) => {
                self.reviews.push(r);
                let codex_done = self.reviews.iter().any(|r| r.reviewer == Agent::Codex);
                if self.effective_complexity() >= 3 && !codex_done {
                    self.launch(Agent::Codex, Step::Feasibility)
                } else {
                    self.pending = None;
                    self.design_review_complete()
                }
            }
            (Phase::SwarmPending, Event::SwarmSpend(true)) => self.begin_swarm(),
            (Phase::SwarmPending, Event::SwarmSpend(false)) => self.stop(Terminal::ParkedRounds),
            (Phase::SwarmGenerate, Event::SwarmCaptured) => {
                self.enter(Phase::SwarmMerge);
                // Covered by the reserve's second Claude invocation.
                self.launch(Agent::Claude, Step::SwarmMerge)
            }
            (Phase::SwarmMerge, Event::Authored(_)) if self.pending == Some(Agent::Claude) => {
                self.enter(Phase::OperatorAcceptMerge);
                self.pending = None;
                Next::AskAcceptMerge
            }
            (Phase::OperatorAcceptMerge, Event::MergeAccepted(true)) => self.accepted_plan(),
            (Phase::OperatorAcceptMerge, Event::MergeAccepted(false)) => {
                self.stop(Terminal::ParkedRejected)
            }
            (Phase::Brief, Event::Authored(_)) if self.pending == Some(Agent::Claude) => {
                self.enter(Phase::BriefReview);
                self.launch(Agent::Codex, Step::BriefReview)
            }
            (Phase::BriefReview, Event::Reviewed(r)) if self.expect_reviewer(&r) => {
                if r.verdict == Verdict::Block {
                    self.stop(Terminal::ParkedBlocked)
                } else if self.accepted(&r) {
                    self.start_impl_round()
                } else {
                    self.start_brief_round()
                }
            }
            (Phase::Implement, Event::Implemented) if self.pending == Some(Agent::Codex) => {
                self.enter(Phase::DiffReview);
                self.launch(Agent::Claude, Step::DiffReview)
            }
            (Phase::DiffReview, Event::Reviewed(r)) if self.expect_reviewer(&r) => {
                if r.verdict == Verdict::Block {
                    self.stop(Terminal::ParkedBlocked)
                } else if self.accepted(&r) {
                    self.enter(Phase::AllowlistApproval);
                    self.pending = None;
                    Next::AskAllowlist
                } else {
                    self.start_impl_round()
                }
            }
            (Phase::AllowlistApproval, Event::AllowlistApproved(true)) => {
                self.enter(Phase::Bundle);
                Next::Bundle
            }
            (Phase::AllowlistApproval, Event::AllowlistApproved(false)) => {
                self.stop(Terminal::ParkedRejected)
            }
            (
                Phase::Bundle,
                Event::Bundled {
                    drift_before,
                    backend_ok,
                    drift_after,
                },
            ) => {
                if drift_before || drift_after {
                    self.stop(Terminal::ParkedDrift)
                } else if !backend_ok {
                    self.stop(Terminal::ParkedInvalid)
                } else {
                    self.stop(Terminal::BundleVerifiedAwaitingOperatorSign)
                }
            }
            (_, other) => {
                let state = self.state;
                self.stop(Terminal::ParkedInvalid);
                return Err(ProtocolError::Unexpected {
                    state,
                    event: format!("{other:?}"),
                });
            }
        };
        Ok(next)
    }
}

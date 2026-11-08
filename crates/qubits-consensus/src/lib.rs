//! Pipelined Moonshot (Doidge et al., DSN 2024) as a sans-I/O state machine.
#![forbid(unsafe_code)]

mod engine;
pub mod shards;
mod types;

pub use engine::{
    App, Config, Engine, Final, Output, REPUTATION_WINDOW, Recent, SafetyState, Start,
};
pub use types::{
    Block, FinalityProof, Header, Message, Proposal, QuorumCert, Round, Timeout, TimeoutCert,
    ValidatorIndex, ValidatorSet, Vote, VoteKind,
};

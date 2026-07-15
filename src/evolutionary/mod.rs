//! Evolutionary fuzzer engine.
//!
//! Architecture: atom-chain generation engine with four decoupled primitives:
//!   - Atom tables (`ATOMS`, `NUMERIC_ATOMS`) — the vocabulary
//!   - `ChainTable` — weighted (prefix, suffix) transitions; 20.0 = near-deterministic
//!   - `PlacementPolicy` — where the generated chain lands (append/prepend/wrap/etc.)
//!   - `LengthPolicy` — geometric stop probability; separate from chain weights
//!
//! `HavocMutator` is the mutation stage (transforms existing payloads).
//! `WeightedSampler::apply_chain` is the generation stage (builds from atoms).
//!
//! Signal classification and the `Mutator` trait are shared from `signals/`.

pub mod atoms;
pub mod corpus;
pub mod evolution;
pub mod havoc;
pub mod rng;

pub use atoms::{
    ATOMS, NUMERIC_ATOMS,
    ChainTable, WeightedSampler,
    PlacementPolicy, Placement,
    LengthPolicy,
    tail_atom, tail_atom_from,
};
pub use havoc::{HavocMutator, HavocOp};
pub use rng::{RngEngine, RngMode};
pub use corpus::{CorpusEntry, SeedCorpus, BoostMode, Feedback, HttpFeedback, FeedbackEval, EvaluationContext};
pub use evolution::{EvolutionaryLoop, EvolutionaryOutcome, EvolutionaryHit, PayloadPolicy};

// Re-export signal/mutator primitives so callers only need one import path.
pub use crate::signals::signal::{
    Signal, SignalSet, ProbeResponse, ReflectionEncoding,
    Classifier, StatusClassifier, SizeClassifier, BodyDiffClassifier,
    ReflectionClassifier, TimeDelayClassifier, ErrorClassifier,
};
pub use crate::signals::mutator::Mutator;
pub use crate::signals::{Probe, Request};

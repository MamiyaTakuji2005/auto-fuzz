//! `auto-fuzz` — a general-purpose evolutionary fuzzer engine.
//!
//! Architecture: atom-chain generation engine with four decoupled primitives:
//!   - Atom tables — the vocabulary
//!   - `ChainTable` — weighted (prefix, suffix) transitions
//!   - `PlacementPolicy` — where the generated chain lands (append/prepend/wrap)
//!   - `LengthPolicy` — geometric stop probability
//!
//! `HavocMutator` is the mutation stage (12 stochastic operators).
//! `WeightedSampler::apply_chain` is the generation stage (builds from atoms).
//! `EvolutionaryLoop` blends both, driven by corpus feedback.
//!
//! Extracted from the [re:Vise](https://github.com/MamiyaTakuji2005/re-Vise) project.

pub mod agent;
pub mod baseline;
pub mod evolutionary;
pub mod payloads;
pub mod signals;

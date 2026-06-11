//! Shared mutation primitives used by `fuzzer_v2` and standalone tools.
//!
//! - `signal`  — classifies what changed between a baseline and a probe response
//! - `mutator` — stateless payload-generation strategies implementing [`Mutator`]
//!
//! The v1 loop drivers (`MutationLoop`, `EvolutionaryLoop`) have been removed.
//! The evolutionary engine now lives in `fuzzer_v2::evolution`.

pub mod mutator;
pub mod signal;

use std::collections::HashMap;
use async_trait::async_trait;

pub use signal::{ProbeResponse, ReflectionEncoding, Signal, SignalSet};
pub use mutator::{Mutator, SignalGuidedMutator, StaticListMutator};

/// A minimal HTTP request fed to a [`Probe`].
#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Send one request and return the raw response.
///
/// Production implementations wrap `FuzzRequestClient`; test implementations
/// return canned responses without any network I/O.
#[async_trait]
pub trait Probe: Send + Sync {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String>;
}

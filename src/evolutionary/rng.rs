//! Dual-mode RNG — `SmallRng` for throughput, `ChaCha12Rng` for replay.

use rand::{RngCore, SeedableRng};
use rand::rngs::SmallRng;
use rand_chacha::ChaCha12Rng;

/// Selects the RNG backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngMode {
    /// `SmallRng` — fast, good for high-throughput unseeded fuzzing.
    /// Algorithm is not guaranteed stable across Rust versions.
    Small,
    /// `ChaCha12Rng` — cryptographically specified, stable across
    /// versions and platforms. Use for seeded replay where you need
    /// the same probe sequence regardless of Rust version or OS.
    ChaCha12,
}

/// A wrapper around either `SmallRng` or `ChaCha12Rng` that implements
/// `RngCore` by delegation. Lets `HavocMutator` and `EvolutionaryLoop`
/// switch backends without generics or dynamic dispatch.
pub enum RngEngine {
    Small(SmallRng),
    ChaCha12(ChaCha12Rng),
}

impl RngEngine {
    /// Create from a mode and a u64 seed.
    pub fn from_seed(mode: RngMode, seed: u64) -> Self {
        match mode {
            RngMode::Small   => Self::Small(SmallRng::seed_from_u64(seed)),
            RngMode::ChaCha12 => Self::ChaCha12(ChaCha12Rng::seed_from_u64(seed)),
        }
    }

    /// Create from a mode, drawing entropy.
    pub fn from_entropy(mode: RngMode) -> Self {
        match mode {
            RngMode::Small   => Self::Small(SmallRng::from_entropy()),
            RngMode::ChaCha12 => Self::ChaCha12(ChaCha12Rng::from_entropy()),
        }
    }

    /// The backend mode.
    pub fn mode(&self) -> RngMode {
        match self {
            Self::Small(_)   => RngMode::Small,
            Self::ChaCha12(_) => RngMode::ChaCha12,
        }
    }
}

impl RngCore for RngEngine {
    fn next_u32(&mut self) -> u32 {
        match self {
            Self::Small(r)   => r.next_u32(),
            Self::ChaCha12(r) => r.next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            Self::Small(r)   => r.next_u64(),
            Self::ChaCha12(r) => r.next_u64(),
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            Self::Small(r)   => r.fill_bytes(dest),
            Self::ChaCha12(r) => r.fill_bytes(dest),
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        match self {
            Self::Small(r)   => r.try_fill_bytes(dest),
            Self::ChaCha12(r) => r.try_fill_bytes(dest),
        }
    }
}

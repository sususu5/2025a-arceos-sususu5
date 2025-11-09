use core::hash::{BuildHasher, Hasher};
use arceos_api::modules::axhal;

// FNV-1a 64-bit hash offset basis
const FNV_OFFSET_BASIS: u64 = 14695981039346656037;

// FNV-1a 64-bit hash prime
const FNV_PRIME: u64 = 1099511628211;

// A FNV hasher
#[derive(Clone, Copy)]
pub struct FnvHasher {
    state: u64,
}

// A FNV hasher must be seeded
impl FnvHasher {
    #[inline]
    pub const fn with_seed(seed: u64) -> Self {
        FnvHasher {
            state: FNV_OFFSET_BASIS ^ seed,
        }
    }
}

impl Hasher for FnvHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= u64::from(byte);
            self.state = self.state.wrapping_mul(FNV_PRIME);
        }
    }
}

// A FNV build hasher
#[derive(Clone, Copy)]
pub struct FnvBuildHasher {
    seed: u64,
}

impl FnvBuildHasher {
    #[inline]
    pub fn new() -> Self {
        let random_value = axhal::misc::random();
        FnvBuildHasher {
            seed: random_value as u64,
        }
    }
}

impl Default for FnvBuildHasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for FnvBuildHasher {
    type Hasher = FnvHasher;

    // Build a new hasher instance using the stored seed
    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FnvHasher::with_seed(self.seed)
    }
}

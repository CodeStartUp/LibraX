//! A tiny deterministic PRNG.
//!
//! The demo environment must be byte-for-byte reproducible from a seed, and it
//! must stay reproducible across dependency upgrades. SplitMix64 is a handful of
//! arithmetic operations with a fixed, published definition, so pinning it here
//! removes both the dependency and the risk of a generator changing under us.

/// SplitMix64. Not cryptographic, and deliberately so: this only generates
/// synthetic telemetry.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in `[low, high)`. Returns `low` if the range is empty.
    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        low + self.next_u64() % (high - low)
    }

    pub fn range_u8(&mut self, low: u8, high: u8) -> u8 {
        self.range(low as u64, high as u64) as u8
    }

    pub fn range_usize(&mut self, low: usize, high: usize) -> usize {
        self.range(low as u64, high as u64) as usize
    }

    pub fn next_f64(&mut self) -> f64 {
        // 53 significant bits, the usual trick for a uniform [0, 1).
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// True with probability `permille / 1000`.
    pub fn chance_permille(&mut self, permille: u64) -> bool {
        self.range(0, 1000) < permille
    }

    pub fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let idx = self.range_usize(0, items.len());
        items.get(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn range_stays_in_bounds() {
        let mut rng = SplitMix64::new(7);
        for _ in 0..1000 {
            let v = rng.range(10, 20);
            assert!((10..20).contains(&v));
        }
        assert_eq!(rng.range(5, 5), 5, "empty range collapses to low bound");
    }

    #[test]
    fn floats_are_unit_interval() {
        let mut rng = SplitMix64::new(99);
        for _ in 0..1000 {
            let v = rng.next_f64();
            assert!((0.0..1.0).contains(&v));
        }
    }
}

use std::net::Ipv4Addr;

use log::debug;
use num::BigInt;

use super::AesRand;

const PRIME: u64 = 4294967311;
const KNOWN_GENERATOR: u64 = 3;
const psub1_f: [u64; 5] = [2, 3, 5, 131, 364289];

fn check_coprime(check: u64) -> bool {
    for &f in psub1_f.iter() {
        if f > check && (f % check == 0) {
            return false;
        } else if f < check && (check % f == 0) {
            return false;
        } else if f == check {
            return false;
        }
    }
    true
}

fn find_generator(aes: &mut AesRand) -> u64 {
    let mut candidate = (aes.get_word() & 0xFFFF) as u64;
    while !check_coprime(candidate) {
        candidate += 1;
    }

    // KNOWN_GENERATOR ^ candidate mod PRIME
    let base = BigInt::from(KNOWN_GENERATOR);
    let exp = BigInt::from(candidate);
    let prime = BigInt::from(PRIME);
    let result = base.modpow(&exp, &prime);

    let digits = result.to_u64_digits().1;
    assert_eq!(digits.len(), 1);
    digits[0]
}

#[derive(Clone)]
pub struct Cyclic {
    generator: u64,
    current: u64,
}

impl Cyclic {
    pub fn new() -> Self {
        let mut aes = AesRand::new();
        let current = (aes.get_word() & 0xFFFF) as u64;
        let mut generator;
        loop {
            generator = find_generator(&mut aes);
            if generator < (1u64 << 32) {
                break;
            }
        }

        debug!(
            "Cyclic initialized with generator: {} and starting point: {}",
            generator,
            Ipv4Addr::from((current as u32).to_be())
        );
        Self { generator, current }
    }

    pub fn current_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from((self.current as u32).to_be())
    }

    // TODO: support blocklist
    pub fn next_ip(&mut self) -> Ipv4Addr {
        loop {
            self.current = (self.current * self.generator) % PRIME;
            if self.current < (1u64 << 32) {
                break;
            }
        }
        Ipv4Addr::from((self.current as u32).to_be())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Run with `cargo test --release -- --include-ignored`
    //
    // We don't check every possible generator, but we can be reasonably sure that the overall
    // logic is correct if this test passes.
    #[ignore]
    #[test]
    fn test_cyclic_coverage() {
        let mut ips: Vec<u64> = vec![0; (1u64 << 32) as usize / 64];
        let mut cyclic = Cyclic::new();
        let starting_point: u32 = cyclic.current_ip().into();

        // We should only need to loop 2^32 - 1 times to hit every IP
        for i in 0..(1u64 << 32) {
            let ip: u32 = cyclic.next_ip().into();

            // Set the bit corresponding to this IP
            let mask = 1u64 << (ip & 0x3F);

            // If the bit is already set, then the generator is incorrect
            assert_eq!(ips[(ip >> 6) as usize] & mask, 0);
            ips[(ip >> 6) as usize] |= mask;

            if ip == starting_point {
                break;
            }
        }

        let num_ips = ips.iter().map(|x| x.count_ones() as u64).sum::<u64>();
        assert_eq!(
            num_ips,
            (1u64 << 32) - 1,
            "Failed with generator: {}",
            cyclic.generator
        );
    }
}

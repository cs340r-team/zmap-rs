use super::AesCtx;
use rand::prelude::*;

pub struct AesRand {
    ctx: AesCtx,
    counter: u128,
}

impl AesRand {
    // TODO: support seed?
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key: [u8; 16] = rng.gen();
        Self {
            ctx: AesCtx::new(&key),
            counter: 0,
        }
    }

    pub fn get_word(&mut self) -> u128 {
        let input = &self.counter.to_be_bytes();
        let output = self.ctx.encrypt(input);
        self.counter += 1;
        u128::from_be_bytes(output)
    }
}

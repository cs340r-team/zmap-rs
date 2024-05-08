use crate::crypto::AesCtx;
use rand::prelude::*;
use std::net::Ipv4Addr;

pub struct ResponseValidator {
    ctx: AesCtx,
}

impl ResponseValidator {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let key: [u8; 16] = rng.gen();
        Self {
            ctx: AesCtx::new(&key),
        }
    }

    pub fn gen(self, src: &Ipv4Addr, dst: &Ipv4Addr) -> [u8; 16] {
        let mut input = [0u8; 16];
        input[0..4].copy_from_slice(&src.octets());
        input[4..8].copy_from_slice(&dst.octets());
        self.ctx.encrypt(&input)
    }
}

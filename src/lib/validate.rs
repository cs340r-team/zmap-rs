use crate::crypto::AesCtx;
use rand::prelude::*;
use std::net::Ipv4Addr;

pub fn new_context() -> AesCtx {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    AesCtx::new(&key)
}

pub fn gen(ctx: &AesCtx, src: &Ipv4Addr, dst: &Ipv4Addr) -> [u8; 16] {
    let mut input = [0u8; 16];
    input[0..4].copy_from_slice(&src.octets());
    input[4..8].copy_from_slice(&dst.octets());
    ctx.encrypt(&input)
}

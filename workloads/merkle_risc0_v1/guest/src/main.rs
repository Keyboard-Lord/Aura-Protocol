#![no_main]
use aura_compute_merkle_v1::{Batch, MAX_INPUT_LEN, INPUT_HEADER_LEN};
use risc0_zkvm::{guest::env, sha::{Impl, Sha256}};
use std::io::Read;
risc0_zkvm::guest::entry!(main);

fn sha256(b: &[u8]) -> [u8;32] { Impl::hash_bytes(b).as_bytes().try_into().unwrap() }
fn main() {
    let mut input = env::stdin();
    let mut job = [0;32]; input.read_exact(&mut job).unwrap();
    let mut len = [0;4]; input.read_exact(&mut len).unwrap();
    let len = u32::from_le_bytes(len) as usize;
    assert!((INPUT_HEADER_LEN..=MAX_INPUT_LEN).contains(&len));
    let mut bytes = vec![0;len]; input.read_exact(&mut bytes).unwrap();
    let mut trailing = [0;1]; assert_eq!(input.read(&mut trailing).unwrap(), 0);
    let batch = Batch::parse(&bytes).unwrap();
    batch.verify(sha256).unwrap();
    env::commit_slice(&batch.journal(job, sha256));
    // Successful normal return is Halted(0). No assumptions or guest verification syscalls.
}

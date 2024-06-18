use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

pub fn gen_key_256(salt: u128, phrase: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(&salt.to_be_bytes());
    hasher.update(phrase);

    let mut key = [0; 32];
    hasher.finalize_variable(&mut key).unwrap();
    key
}

pub fn gen_key_384(salt: u128, phrase: &[u8]) -> [u8; 48] {
    let mut hasher = Blake2bVar::new(48).unwrap();
    hasher.update(&salt.to_be_bytes());
    hasher.update(phrase);

    let mut key = [0; 48];
    hasher.finalize_variable(&mut key).unwrap();
    key
}

pub fn gen_key_512(salt: u128, phrase: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2bVar::new(64).unwrap();
    hasher.update(&salt.to_be_bytes());
    hasher.update(phrase);

    let mut key = [0; 64];
    hasher.finalize_variable(&mut key).unwrap();
    key
}

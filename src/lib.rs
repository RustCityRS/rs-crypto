//! RuneScape Cryptography Utilities
//!
//! Provides cryptographic primitives used by RuneScape:
//! - RSA: Login block encryption/decryption
//! - ISAAC: Stream cipher for packet encryption
//! - Tiny key (XTEA): Block cipher for map region encryption
//! - Huffman: Chat message compression
//! - Whirlpool: Cache reference table hashing

pub mod huffman;
pub mod isaac;
pub mod rsa;
pub mod tinykey;
mod whirlpool;

pub fn whirlpool(data: &[u8]) -> [u8; 64] {
    self::whirlpool::whirlpool(data)
}

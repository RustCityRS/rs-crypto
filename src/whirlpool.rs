// Whirlpool hash function (512-bit digest).
// NESSIE reference implementation by Paulo S.L.M. Barreto and Vincent Rijmen.
// Core algorithm is the C reference implementation (version 3.0, 2003.03.12).

use std::ffi::{c_int, c_uchar, c_ulong};
use std::mem::MaybeUninit;

#[repr(C)]
struct NESSIEstruct {
    bit_length: [c_uchar; 32],
    buffer: [c_uchar; 64],
    buffer_bits: c_int,
    buffer_pos: c_int,
    hash: [u64; 8],
}

unsafe extern "C" {
    fn NESSIEinit(structpointer: *mut NESSIEstruct);
    fn NESSIEadd(source: *const c_uchar, source_bits: c_ulong, structpointer: *mut NESSIEstruct);
    fn NESSIEfinalize(structpointer: *mut NESSIEstruct, result: *mut c_uchar);
}

pub fn whirlpool(data: &[u8]) -> [u8; 64] {
    unsafe {
        let mut state = MaybeUninit::<NESSIEstruct>::uninit();
        NESSIEinit(state.as_mut_ptr());
        let state = state.assume_init_mut();

        NESSIEadd(data.as_ptr(), (data.len() as c_ulong) * 8, state);

        let mut digest = [0u8; 64];
        NESSIEfinalize(state, digest.as_mut_ptr());
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        let hash = whirlpool(b"");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash[0..8], [0x19, 0xFA, 0x61, 0xD7, 0x55, 0x22, 0xA4, 0x66]);
    }

    #[test]
    fn test_abc() {
        let hash = whirlpool(b"abc");
        assert_eq!(hash[0..8], [0x4E, 0x24, 0x48, 0xA4, 0xC6, 0xF4, 0x86, 0xBB]);
    }

    #[test]
    fn test_deterministic() {
        assert_eq!(whirlpool(b"test"), whirlpool(b"test"));
    }

    #[test]
    fn test_different_inputs() {
        assert_ne!(whirlpool(b"a"), whirlpool(b"b"));
    }

    #[test]
    fn test_quick_brown_fox() {
        let hash = whirlpool(b"The quick brown fox jumps over the lazy dog");
        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0xB9, 0x7D, 0xE5, 0x12, 0xE9, 0x1E, 0x38, 0x28,
            0xB4, 0x0D, 0x2B, 0x0F, 0xDC, 0xE9, 0xCE, 0xB3,
            0xC4, 0xA7, 0x1F, 0x9B, 0xEA, 0x8D, 0x88, 0xE7,
            0x5C, 0x4F, 0xA8, 0x54, 0xDF, 0x36, 0x72, 0x5F,
            0xD2, 0xB5, 0x2E, 0xB6, 0x54, 0x4E, 0xDC, 0xAC,
            0xD6, 0xF8, 0xBE, 0xDD, 0xFE, 0xA4, 0x03, 0xCB,
            0x55, 0xAE, 0x31, 0xF0, 0x3A, 0xD6, 0x2A, 0x5E,
            0xF5, 0x4E, 0x42, 0xEE, 0x82, 0xC3, 0xFB, 0x35,
        ];
        assert_eq!(hash, expected);
    }
}

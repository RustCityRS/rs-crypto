use std::fmt::Debug;
use std::os::raw::c_int;

const RANDSIZ: usize = 256;

#[repr(C)]
struct RandCtx {
    randcnt: u32,
    randrsl: [u32; RANDSIZ],
    randmem: [u32; RANDSIZ],
    randa: u32,
    randb: u32,
    randc: u32,
}

unsafe extern "C" {
    fn randinit(ctx: *mut RandCtx, flag: c_int);
    fn isaac(ctx: *mut RandCtx);
}

#[derive(Clone)]
pub struct Isaac {
    ctx: RandCtx,
}

impl Debug for Isaac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Isaac").finish_non_exhaustive()
    }
}

impl Clone for RandCtx {
    fn clone(&self) -> Self {
        Self {
            randcnt: self.randcnt,
            randrsl: self.randrsl,
            randmem: self.randmem,
            randa: self.randa,
            randb: self.randb,
            randc: self.randc,
        }
    }
}

impl Isaac {
    pub fn new(seed: &[u32; 4]) -> Self {
        let mut ctx = RandCtx {
            randcnt: 0,
            randrsl: [0; RANDSIZ],
            randmem: [0; RANDSIZ],
            randa: 0,
            randb: 0,
            randc: 0,
        };

        ctx.randrsl[..4].copy_from_slice(seed);

        unsafe {
            randinit(&mut ctx, 1);
        }

        Self { ctx }
    }

    pub fn next_int(&mut self) -> u32 {
        if self.ctx.randcnt == 0 {
            unsafe {
                isaac(&mut self.ctx);
            }
            self.ctx.randcnt = RANDSIZ as u32;
        }
        self.ctx.randcnt -= 1;
        self.ctx.randrsl[self.ctx.randcnt as usize]
    }

    pub fn next_int_max(&mut self, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        self.next_int() % max
    }

    pub fn next_int_range(&mut self, min: i32, max: i32) -> i32 {
        min + (self.next_int() % (max - min) as u32) as i32
    }
}

#[derive(Debug, Clone)]
pub struct IsaacPair {
    pub decode: Isaac,
    pub encode: Isaac,
}

impl IsaacPair {
    pub fn new(decode_seed: &[u32; 4], encode_seed: &[u32; 4]) -> Self {
        Self {
            decode: Isaac::new(decode_seed),
            encode: Isaac::new(encode_seed),
        }
    }

    pub fn from_client_seeds(seeds: &[i32; 4]) -> Self {
        let decode_seed: [u32; 4] = [
            seeds[0] as u32,
            seeds[1] as u32,
            seeds[2] as u32,
            seeds[3] as u32,
        ];
        let encode_seed: [u32; 4] = [
            (seeds[0] + 50) as u32,
            (seeds[1] + 50) as u32,
            (seeds[2] + 50) as u32,
            (seeds[3] + 50) as u32,
        ];
        Self {
            decode: Isaac::new(&decode_seed),
            encode: Isaac::new(&encode_seed),
        }
    }

    pub fn from_session_key(session_key: u64) -> ([u32; 4], [u32; 4]) {
        let key_low = session_key as u32;
        let key_high = (session_key >> 32) as u32;

        let decode_seed = [
            key_low,
            key_high,
            key_low.wrapping_add(1),
            key_high.wrapping_add(1),
        ];
        let encode_seed = [
            key_low ^ 0xDEADBEEF,
            key_high ^ 0xCAFEBABE,
            key_low.wrapping_sub(1),
            key_high.wrapping_sub(1),
        ];

        (decode_seed, encode_seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isaac_deterministic() {
        let seed = [0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210];

        let mut isaac1 = Isaac::new(&seed);
        let mut isaac2 = Isaac::new(&seed);

        for _ in 0..1000 {
            assert_eq!(isaac1.next_int(), isaac2.next_int());
        }
    }

    #[test]
    fn test_isaac_different_values() {
        let seed = [0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210];
        let mut isaac = Isaac::new(&seed);

        let v1 = isaac.next_int();
        let v2 = isaac.next_int();
        let v3 = isaac.next_int();

        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
    }

    #[test]
    fn test_isaac_pair() {
        let session_key = 0x0123456789ABCDEF;
        let (decode_seed, encode_seed) = IsaacPair::from_session_key(session_key);
        let _pair = IsaacPair::new(&decode_seed, &encode_seed);
    }

    #[test]
    fn test_different_seeds_produce_different_sequences() {
        let mut a = Isaac::new(&[1, 2, 3, 4]);
        let mut b = Isaac::new(&[5, 6, 7, 8]);

        let seq_a: Vec<u32> = (0..10).map(|_| a.next_int()).collect();
        let seq_b: Vec<u32> = (0..10).map(|_| b.next_int()).collect();
        assert_ne!(seq_a, seq_b);
    }

    #[test]
    fn test_zero_seed() {
        let mut isaac = Isaac::new(&[0, 0, 0, 0]);
        let v1 = isaac.next_int();
        let v2 = isaac.next_int();
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_next_int_max_zero() {
        let mut isaac = Isaac::new(&[1, 2, 3, 4]);
        assert_eq!(isaac.next_int_max(0), 0);
    }

    #[test]
    fn test_next_int_max_bounds() {
        let mut isaac = Isaac::new(&[1, 2, 3, 4]);
        for _ in 0..1000 {
            assert!(isaac.next_int_max(100) < 100);
        }
    }

    #[test]
    fn test_next_int_range_bounds() {
        let mut isaac = Isaac::new(&[1, 2, 3, 4]);
        for _ in 0..1000 {
            let v = isaac.next_int_range(10, 20);
            assert!((10..20).contains(&v));
        }
    }

    #[test]
    fn test_clone_produces_independent_state() {
        let mut original = Isaac::new(&[1, 2, 3, 4]);
        for _ in 0..10 {
            original.next_int();
        }

        let mut cloned = original.clone();
        assert_eq!(original.next_int(), cloned.next_int());

        original.next_int();
        let v_orig = original.next_int();
        let v_clone = cloned.next_int();
        assert_ne!(v_orig, v_clone);
    }

    #[test]
    fn test_exhausts_multiple_batches() {
        let mut isaac = Isaac::new(&[1, 2, 3, 4]);
        let mut values = std::collections::HashSet::new();
        for _ in 0..1000 {
            values.insert(isaac.next_int());
        }
        assert!(values.len() > 900);
    }

    #[test]
    fn test_from_client_seeds() {
        let client_seeds: [i32; 4] = [100, 200, 300, 400];
        let pair = IsaacPair::from_client_seeds(&client_seeds);

        let mut decode_check = Isaac::new(&[100, 200, 300, 400]);
        let mut encode_check = Isaac::new(&[150, 250, 350, 450]);

        assert_eq!(pair.decode.clone().next_int(), decode_check.next_int());
        assert_eq!(pair.encode.clone().next_int(), encode_check.next_int());
    }

    #[test]
    fn test_from_session_key_values() {
        let session_key: u64 = 0x0123456789ABCDEF;
        let key_low = session_key as u32;
        let key_high = (session_key >> 32) as u32;

        let (decode, encode) = IsaacPair::from_session_key(session_key);

        assert_eq!(decode[0], key_low);
        assert_eq!(decode[1], key_high);
        assert_eq!(decode[2], key_low.wrapping_add(1));
        assert_eq!(decode[3], key_high.wrapping_add(1));

        assert_eq!(encode[0], key_low ^ 0xDEADBEEF);
        assert_eq!(encode[1], key_high ^ 0xCAFEBABE);
        assert_eq!(encode[2], key_low.wrapping_sub(1));
        assert_eq!(encode[3], key_high.wrapping_sub(1));
    }

    #[test]
    fn test_decode_encode_are_independent() {
        let pair = IsaacPair::new(&[1, 2, 3, 4], &[5, 6, 7, 8]);
        let mut decode = pair.decode;
        let mut encode = pair.encode;

        let decode_vals: Vec<u32> = (0..10).map(|_| decode.next_int()).collect();
        let encode_vals: Vec<u32> = (0..10).map(|_| encode.next_int()).collect();
        assert_ne!(decode_vals, encode_vals);
    }
}

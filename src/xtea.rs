// XTEA (eXtended Tiny Encryption Algorithm) block cipher.
// 128-bit key, 64-bit block, Feistel network.
// Core algorithm is the reference C implementation from Wikipedia (public domain).

unsafe extern "C" {
    fn encipher(num_rounds: u32, v: *mut u32, key: *const u32);
    fn decipher(num_rounds: u32, v: *mut u32, key: *const u32);
}

pub struct Xtea;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XteaError {
    InvalidLength,
}

impl std::fmt::Display for XteaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XteaError::InvalidLength => write!(f, "Data length must be a multiple of 8"),
        }
    }
}

impl std::error::Error for XteaError {}

pub type Result<T> = std::result::Result<T, XteaError>;

impl Xtea {
    pub const ROUNDS: u32 = 32;

    pub fn encrypt(data: &mut [u8], key: &[u32; 4]) -> Result<()> {
        Self::encrypt_with_rounds(data, key, Self::ROUNDS)
    }

    pub fn decrypt(data: &mut [u8], key: &[u32; 4]) -> Result<()> {
        Self::decrypt_with_rounds(data, key, Self::ROUNDS)
    }

    pub fn encrypt_with_rounds(data: &mut [u8], key: &[u32; 4], rounds: u32) -> Result<()> {
        if !data.len().is_multiple_of(8) {
            return Err(XteaError::InvalidLength);
        }

        for chunk in data.chunks_exact_mut(8) {
            let mut v: [u32; 2] = [
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            ];

            unsafe {
                encipher(rounds, v.as_mut_ptr(), key.as_ptr());
            }

            chunk[0..4].copy_from_slice(&v[0].to_be_bytes());
            chunk[4..8].copy_from_slice(&v[1].to_be_bytes());
        }

        Ok(())
    }

    pub fn decrypt_with_rounds(data: &mut [u8], key: &[u32; 4], rounds: u32) -> Result<()> {
        if !data.len().is_multiple_of(8) {
            return Err(XteaError::InvalidLength);
        }

        for chunk in data.chunks_exact_mut(8) {
            let mut v: [u32; 2] = [
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            ];

            unsafe {
                decipher(rounds, v.as_mut_ptr(), key.as_ptr());
            }

            chunk[0..4].copy_from_slice(&v[0].to_be_bytes());
            chunk[4..8].copy_from_slice(&v[1].to_be_bytes());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key: [u32; 4] = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210];
        let original = b"ABCDEFGH";
        let mut data = original.to_vec();

        Xtea::encrypt(&mut data, &key).unwrap();
        assert_ne!(&data, original);

        Xtea::decrypt(&mut data, &key).unwrap();
        assert_eq!(&data, original);
    }

    #[test]
    fn test_invalid_length() {
        let key: [u32; 4] = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210];
        let mut data = vec![1u8, 2, 3, 4, 5];
        assert_eq!(
            Xtea::decrypt(&mut data, &key),
            Err(XteaError::InvalidLength)
        );
    }

    #[test]
    fn test_multiple_blocks() {
        let key: [u32; 4] = [0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xC0DED00D];
        let original = b"ABCDEFGHJKLMNOPQ";
        let mut data = original.to_vec();

        Xtea::encrypt(&mut data, &key).unwrap();
        Xtea::decrypt(&mut data, &key).unwrap();
        assert_eq!(&data, original);
    }

    #[test]
    fn test_zero_key_roundtrip() {
        let key: [u32; 4] = [0, 0, 0, 0];
        let mut data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        Xtea::encrypt(&mut data, &key).unwrap();
        Xtea::decrypt(&mut data, &key).unwrap();
        assert_eq!(data, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_decrypt_with_custom_rounds() {
        let key: [u32; 4] = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210];
        let original = b"TESTDATA";
        let mut data = original.to_vec();

        Xtea::encrypt(&mut data, &key).unwrap();
        Xtea::decrypt_with_rounds(&mut data, &key, 32).unwrap();
        assert_eq!(&data, original);
    }
}

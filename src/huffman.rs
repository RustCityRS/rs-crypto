/// Huffman codec for RuneScape chat messages.
///
/// Builds a canonical Huffman code from a bit-length table (one byte per symbol,
/// typically 256 entries loaded from the cache). Provides encode/decode for raw
/// byte buffers — string handling is left to the caller.
pub struct Huffman {
    codewords: Vec<i32>,
    bits: Vec<u8>,
    symbol_tree: Vec<i32>,
}

impl Huffman {
    /// Build the codec from a bit-length table.
    pub fn new(bit_lengths: &[u8]) -> Self {
        let symbols = bit_lengths.len();
        let mut codewords = vec![0i32; symbols];
        let bits = bit_lengths.to_vec();
        let mut next_codewords = [0i32; 33];
        let mut symbol_tree = vec![0i32; 8];
        let mut next_node: i32 = 0;

        for symbol in 0..symbols {
            let codeword_bits = bits[symbol];
            if codeword_bits == 0 {
                continue;
            }
            let bit = 1i32 << (32 - codeword_bits as i32);
            let codeword = next_codewords[codeword_bits as usize];
            codewords[symbol] = codeword;

            let updated;
            if (bit & codeword) == 0 {
                updated = codeword | bit;
                for i in (1..codeword_bits as usize).rev() {
                    let next_cw = next_codewords[i];
                    if codeword != next_cw {
                        break;
                    }
                    let bit2 = 1i32 << (32 - i as i32);
                    if (next_cw & bit2) != 0 {
                        next_codewords[i] = next_codewords[i - 1];
                        break;
                    }
                    next_codewords[i] = next_cw | bit2;
                }
            } else {
                updated = next_codewords[codeword_bits as usize - 1];
            }

            next_codewords[codeword_bits as usize] = updated;
            for entry in &mut next_codewords[(codeword_bits as usize + 1)..=32] {
                if codeword == *entry {
                    *entry = updated;
                }
            }

            let mut node: i32 = 0;
            for i in 0..codeword_bits as i32 {
                let mask = (i32::MIN as u32 >> i as u32) as i32;
                if (codeword & mask) == 0 {
                    node += 1;
                } else {
                    if symbol_tree[node as usize] == 0 {
                        symbol_tree[node as usize] = next_node;
                    }
                    node = symbol_tree[node as usize];
                }
                if node as usize >= symbol_tree.len() {
                    symbol_tree.resize(symbol_tree.len() * 2, 0);
                }
            }
            symbol_tree[node as usize] = !(symbol as i32);
            if node >= next_node {
                next_node = node + 1;
            }
        }

        Self {
            codewords,
            bits,
            symbol_tree,
        }
    }

    /// Encode `src` into Huffman-compressed bytes in `dest`.
    /// Returns the number of bytes written.
    pub fn encode(&self, src: &[u8], dest: &mut [u8]) -> usize {
        let mut prev_codeword: i32 = 0;
        let mut bit_pos: i32 = 0;

        for &sym in src {
            let symbol = sym as usize;
            let codeword = self.codewords[symbol] as u32;
            let codeword_bits = self.bits[symbol];
            if codeword_bits == 0 {
                continue;
            }

            let byte_pos = (bit_pos >> 3) as usize;
            let bit_off = bit_pos & 7;
            let masked = prev_codeword & ((-bit_off) >> 31);
            let end_byte_pos = ((bit_off + codeword_bits as i32 - 1) >> 3) as usize + byte_pos;
            let shift = (bit_off + 24) as u32;

            prev_codeword = masked | (codeword >> shift) as i32;
            dest[byte_pos] = prev_codeword as u8;

            if end_byte_pos > byte_pos {
                let p1 = byte_pos + 1;
                let s1 = shift - 8;
                prev_codeword = (codeword >> s1) as i32;
                dest[p1] = prev_codeword as u8;

                if p1 < end_byte_pos {
                    let p2 = p1 + 1;
                    let s2 = s1 - 8;
                    prev_codeword = (codeword >> s2) as i32;
                    dest[p2] = prev_codeword as u8;

                    if end_byte_pos > p2 {
                        let p3 = p2 + 1;
                        let s3 = s2 - 8;
                        prev_codeword = (codeword >> s3) as i32;
                        dest[p3] = prev_codeword as u8;

                        if p3 < end_byte_pos {
                            let s4 = 32 - s3;
                            let p4 = p3 + 1;
                            prev_codeword = (codeword << s4) as i32;
                            dest[p4] = prev_codeword as u8;
                        }
                    }
                }
            }

            bit_pos += codeword_bits as i32;
        }

        ((bit_pos + 7) >> 3) as usize
    }

    /// Decode `len` symbols from Huffman-compressed `src[src_off..]` into `dest`.
    /// Returns the number of source bytes consumed.
    pub fn decode(&self, src: &[u8], src_off: usize, dest: &mut [u8], len: usize) -> usize {
        if len == 0 {
            return 0;
        }

        let mut dest_off: usize = 0;
        let mut src_pos = src_off;
        let mut node: i32 = 0;

        'outer: loop {
            let b = src[src_pos] as i8;

            macro_rules! step {
                ($mask:expr) => {
                    let next = if (b as i32 & $mask) == 0 {
                        node + 1
                    } else {
                        self.symbol_tree[node as usize]
                    };
                    let val = self.symbol_tree[next as usize];
                    if val < 0 {
                        dest[dest_off] = (!val) as u8;
                        dest_off += 1;
                        if dest_off >= len {
                            break 'outer;
                        }
                        node = 0;
                    } else {
                        node = next;
                    }
                };
            }

            let next = if b < 0 {
                self.symbol_tree[node as usize]
            } else {
                node + 1
            };
            let val = self.symbol_tree[next as usize];
            if val < 0 {
                dest[dest_off] = (!val) as u8;
                dest_off += 1;
                if dest_off >= len {
                    break;
                }
                node = 0;
            } else {
                node = next;
            }

            step!(0x40);
            step!(0x20);
            step!(0x10);
            step!(0x08);
            step!(0x04);
            step!(0x02);
            step!(0x01);

            src_pos += 1;
        }

        src_pos + 1 - src_off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_table() -> Vec<u8> {
        let mut bits = vec![0u8; 256];
        bits[b'a' as usize] = 1;
        bits[b'b' as usize] = 2;
        bits[b'c' as usize] = 3;
        bits[b'd' as usize] = 3;
        bits
    }

    #[test]
    fn roundtrip() {
        let h = Huffman::new(&test_table());
        let src = b"abcd";
        let mut compressed = vec![0u8; 64];
        let written = h.encode(src, &mut compressed);
        compressed.truncate(written);

        let mut decoded = vec![0u8; src.len()];
        h.decode(&compressed, 0, &mut decoded, src.len());
        assert_eq!(&decoded, src);
    }

    #[test]
    fn empty() {
        let h = Huffman::new(&test_table());
        let src: &[u8] = b"";
        let mut compressed = vec![0u8; 64];
        let written = h.encode(src, &mut compressed);
        assert_eq!(written, 0);
        assert_eq!(h.decode(&compressed, 0, &mut [], 0), 0);
    }

    #[test]
    fn single_char() {
        let h = Huffman::new(&test_table());
        let src = b"a";
        let mut compressed = vec![0u8; 64];
        let written = h.encode(src, &mut compressed);
        compressed.truncate(written);

        let mut decoded = vec![0u8; 1];
        h.decode(&compressed, 0, &mut decoded, 1);
        assert_eq!(&decoded, src);
    }

    #[test]
    fn repeated() {
        let h = Huffman::new(&test_table());
        let src = b"aaaa";
        let mut compressed = vec![0u8; 64];
        let written = h.encode(src, &mut compressed);
        compressed.truncate(written);

        let mut decoded = vec![0u8; src.len()];
        h.decode(&compressed, 0, &mut decoded, src.len());
        assert_eq!(&decoded, src);
    }
}

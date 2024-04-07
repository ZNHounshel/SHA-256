use std::mem::size_of;

pub mod sha2_hasher;

pub const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
pub const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn calculate_extended_words(block: &[u8; 64]) -> [u32; 64] {
    let mut extended_words = [0u32; 64];
    let int_size = size_of::<u32>();
    for i in 0..(64 / int_size) {
        extended_words[i] = u32::from_be_bytes(block[(i * int_size)..(i * int_size + int_size)].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = extended_words[i - 15].rotate_right(7)
            ^ extended_words[i - 15].rotate_right(18)
            ^ (extended_words[i - 15] >> 3);
        let s1 = extended_words[i - 2].rotate_right(17)
            ^ extended_words[i - 2].rotate_right(19)
            ^ (extended_words[i - 2] >> 10);
        extended_words[i] = s1
            .wrapping_add(s0)
            .wrapping_add(extended_words[i - 16])
            .wrapping_add(extended_words[i - 7]);
    }
    extended_words
}

pub fn ma(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

pub fn s0(a: u32) -> u32 {
    a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)
}

pub fn s1(e: u32) -> u32 {
    e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)
}

pub fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

#[cfg(test)]
mod test {
    use crate::{calculate_extended_words, ch, ma, s0, s1, ROUND_CONSTANTS};

    #[test]
    /// Set of pre-known values for each stage of the SHA256 processes
    fn validate_special_func() {
        let ch_v = ch(0x510e527f, 0x9b05688c, 0x1f83d9ab);
        assert_eq!(ch_v, 0x1f85c98c, "Ch function returned incorrect value");
        let ma_v = ma(0x6a09e667, 0xbb67ae85, 0x3c6ef372);
        assert_eq!(ma_v, 0x3a6fe667, "Ma function returned incorrect value");
        let s0_v = s0(0x6a09e667);
        assert_eq!(s0_v, 0xce20b47e, "s0 function returned incorrect value");
        let s1_v = s1(0x510e527f);
        assert_eq!(s1_v, 0x3587272b, "s1 function returned incorrect value");
        let sum1 = 0x54657374u32.wrapping_add(ROUND_CONSTANTS[0]);
        assert_eq!(sum1, 0x96efa30c);
        let sum2 = ch_v.wrapping_add(sum1).wrapping_add(0x5be0cd19);
        assert_eq!(sum2, 0x125639b1);
        let sum3 = s1_v.wrapping_add(sum2);
        assert_eq!(sum3, 0x47dd60dc);
        let sum4 = sum3.wrapping_add(ma_v);
        assert_eq!(sum4, 0x824d4743);
        let sum5 = sum4.wrapping_add(s0_v);
        assert_eq!(sum5, 0x506dfbc1);
    }

    #[test]
    fn extend_block() {
        let mut x = "Tests are  just\nthe right size\nfor 9 bytes\nat the end.\n"
            .bytes()
            .collect::<Vec<_>>();
        let x_len = x.len();
        x.push(0x80);
        x.extend(vec![0; 64 - x_len - 8 - 1]);
        x.extend((x_len as u64).to_le_bytes());
        assert_eq!(x.len(), 64);
        // let (_, x, _) = unsafe { x.align_to::<u32>() };

        let extended_block = calculate_extended_words(x.as_slice().try_into().unwrap());
        for (i, v) in extended_block.iter().enumerate() {
            println!("W[{i:0>2}] = 0x{v:0<8x}");
        }
    }
}

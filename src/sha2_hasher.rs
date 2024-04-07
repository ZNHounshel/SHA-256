use std::{fmt::Display, mem::size_of};

use log::trace;

use crate::{calculate_extended_words, ch, ma, s0, s1, INITIAL_STATE, ROUND_CONSTANTS};

const SHA256_BLOCKS: usize = 64;
pub struct SHAState {
    values: [u32; 8],
    length: usize,
    pending_count: usize,
    pending: [u8; SHA256_BLOCKS],
}

impl Default for SHAState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Hash {
    value: [u32; 8],
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for v in self.value {
            write!(f, "{v:08x}")?
        }
        Ok(())
    }
}
impl SHAState {
    pub fn new() -> SHAState {
        SHAState {
            values: INITIAL_STATE,
            length: 0,
            pending_count: 0,
            pending: [0; SHA256_BLOCKS],
        }
    }

    fn process_block(&mut self) {
        assert_eq!(self.pending_count, SHA256_BLOCKS);
        let w = calculate_extended_words(&self.pending);
        trace!("SHA2 Block {:?}", w);
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.values;
        for i in 0..SHA256_BLOCKS {
            let term_a = ROUND_CONSTANTS[i]
                .wrapping_add(w[i])
                .wrapping_add(ch(e, f, g))
                .wrapping_add(h)
                .wrapping_add(s1(e));
            let term_b = s0(a).wrapping_add(ma(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(term_a);
            d = c;
            c = b;
            b = a;
            a = term_a.wrapping_add(term_b);
            trace!(
                "Round {:?} {:08x?} {:08x?} {:08x?} {:08x?} {:08x?} {:08x?} {:08x?} {:08x?}",
                i,
                a,
                b,
                c,
                d,
                e,
                f,
                g,
                h
            );
        }
        self.values
            .iter_mut()
            .zip([a, b, c, d, e, f, g, h])
            .for_each(|(a, b)| *a = a.wrapping_add(b));
        self.pending_count = 0;
    }

    pub fn update(&mut self, data: &[u8]) {
        self.length += data.len();
        let mut data = data;

        // Consume entire blocks of data while they're available
        while data.len() + self.pending_count >= SHA256_BLOCKS {
            let (block, rest) = data.split_at(SHA256_BLOCKS - self.pending_count);
            self.pending[self.pending_count..].copy_from_slice(block);
            self.pending_count += block.len();
            self.process_block();
            data = rest;
        }

        // Store the remaining in pending
        self.pending[self.pending_count..self.pending_count + data.len()].copy_from_slice(data);
        self.pending_count += data.len();
    }

    pub fn digest(&mut self) -> Hash {
        // Convert bytes to bits big-endian
        let final_length = ((self.length * 8) as u64).to_be_bytes();

        // Add a 1 bit to the end of the message.
        self.update(&[0x80]);

        // If there is insufficient space for the length in the current block, pad it with zeros
        if self.pending_count > SHA256_BLOCKS - size_of::<u64>() {
            self.update(&vec![0; SHA256_BLOCKS - self.pending_count]);
        }

        // Pad the final block of the hash with zeroes and the length at the end
        self.update(&vec![
            0;
            SHA256_BLOCKS - size_of::<u64>() - self.pending_count
        ]);
        self.update(&final_length);

        // Return the hash and reset
        let value = self.values;
        self.reset();
        Hash { value }
    }

    fn reset(&mut self) {
        self.values = INITIAL_STATE;
        self.length = 0;
        self.pending_count = 0;
        self.pending = [0; SHA256_BLOCKS];
    }
}

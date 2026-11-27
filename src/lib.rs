#![no_std]
use base64ct::{Base64, Encoding};
use consts::*;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keyfile([u8; KEYFILE_LEN]);

pub enum KeyfileError {
    BadLength { expected: usize },
}

impl TryFrom<&[u8]> for Keyfile {
    type Error = KeyfileError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut ret = Self([0u8; _]);
        if value.len() == KEYFILE_LEN {
            ret.0.copy_from_slice(value);
            Ok(ret)
        } else {
            Err(Self::Error::BadLength {
                expected: KEYFILE_LEN,
            })
        }
    }
}

impl Keyfile {
    pub fn gen_key<'a>(self, seed: &str, key_buf: &'a mut [u8; KEY_BUF_LEN]) -> &'a str {
        let mut hasher = Sha256::new_with_prefix(&self.0[IV_RANGE]);

        for part in seed.split_ascii_whitespace() {
            hasher.update(part);
        }

        loop {
            let hash = hasher.clone().finalize();

            let key = Base64::encode(&hash[..KEY_LEN], key_buf)
                .expect("Valid base64 length should be guaranteed by `consts::KEY_LEN`");

            // NOTE Due to inability to `zeroize` the hasher, fuzz it further
            hasher.update(&hash[RESEED_RANGE]);

            if Self::check_formatting(key) {
                break;
            }
        }

        // SAFETY It's a base64 string, therefore valid UTF-8
        unsafe { str::from_utf8_unchecked(&key_buf[..]) }
    }

    fn check_formatting(key: &str) -> bool {
        if key.len() != KEY_BUF_LEN {
            return false;
        }

        let mut upper = false;
        let mut lower = false;
        let mut digits = false;
        let mut plus_count = 0;
        let mut other_count = 0;

        for b in key.bytes() {
            if b.is_ascii_uppercase() {
                upper = true;
            } else if b.is_ascii_lowercase() {
                lower = true;
            } else if b.is_ascii_digit() {
                digits = true;
            } else if b == b'+' {
                plus_count += 1;
            } else {
                other_count += 1;
            }
        }

        plus_count == 1 && other_count == 0 && upper && lower && digits
    }
}

pub mod consts {
    use core::ops::Range;

    pub const KEYFILE_LEN: usize = 128;

    pub const KEY_LEN: usize = 9;
    pub const KEY_BUF_LEN: usize = KEY_LEN.div_ceil(3) * 4;

    pub const IV_RANGE: Range<usize> = 0..32;
    pub const RESEED_RANGE: Range<usize> = 0..32;
}

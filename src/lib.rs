use std::{
    fmt,
    fs::File,
    io::{Error, Read, Write},
    ops::Range,
    path::Path,
};

use base64ct::{Base64, Encoding};
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct Keyfile {
    data: [u8; 128 + 1],
    can_save: bool,
}

#[derive(Debug)]
pub enum KeyfileError {
    BadLength,
    Other(Error),
}

impl Keyfile {
    const HASH_RANGE: Range<usize> = 0..12;
    pub const PW_SIZE: usize = (Self::HASH_RANGE.end - Self::HASH_RANGE.start).div_ceil(3) * 4;

    pub fn new_from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyfileError> {
        let mut ret = Self {
            data: [0; _],
            can_save: false,
        };
        let mut file = File::open(path).map_err(KeyfileError::Other)?;

        match file.read(&mut ret.data) {
            Ok(128) => Ok(ret),
            Ok(_) => Err(KeyfileError::BadLength),
            Err(err) => Err(KeyfileError::Other(err)),
        }
    }

    pub fn new_random(mut rng: impl Rng) -> Self {
        let mut ret = Self {
            data: [0; _],
            can_save: true,
        };
        rng.fill_bytes(&mut ret.data);
        ret
    }

    pub fn derive_pass<S: AsRef<str>>(self, seed: S, output: &mut [u8; Self::PW_SIZE]) {
        const IV_RANGE: Range<usize> = 0..32;

        let seed = seed.as_ref();

        let mut hasher = Sha256::new_with_prefix(&self.data[IV_RANGE]);

        for part in seed.split_whitespace() {
            hasher.update(part);
        }

        loop {
            let mut hash = hasher.clone().finalize();
            Base64::encode(&hash[Self::HASH_RANGE], output)
                .expect("`Self::PW_SIZE` should match the encoded length for `Self::HASH_RANGE`");

            if Self::is_strong_enough(output) {
                break;
            }

            hasher.update(hash);
            hash.zeroize();
        }

        hasher.update([0u8; IV_RANGE.end - IV_RANGE.start])
    }

    pub fn save_to<P: AsRef<Path>>(self, path: P) -> Result<(), KeyfileError> {
        const KEYFILE_RANGE: Range<usize> = 0..128;

        match (self.can_save, File::create_new(path)) {
            (true, Ok(mut file)) => file
                .write(&self.data[KEYFILE_RANGE])
                .map(|_| ())
                .map_err(KeyfileError::Other),
            (false, Ok(_)) => unreachable!("'Tis should NOT happen. Ever."),
            (_, Err(err)) => Err(KeyfileError::Other(err)),
        }
    }

    pub fn extract_symm_to<P: AsRef<Path>>(self, path: P) -> Result<(), KeyfileError> {
        const SYMM_RANGE: Range<usize> = 96..128;

        File::create_new(path)
            .map_err(KeyfileError::Other)?
            .write(&self.data[SYMM_RANGE])
            .map(|_| ())
            .map_err(KeyfileError::Other)
    }

    fn is_strong_enough(password: &[u8; Self::PW_SIZE]) -> bool {
        const HAS_UPPER: u8 = 1 << 0;
        const HAS_LOWER: u8 = 1 << 1;
        const HAS_DIGIT: u8 = 1 << 2;
        const ALL: u8 = HAS_UPPER | HAS_LOWER | HAS_DIGIT;
        const SYMBOL_SHIFT: u8 = 3;

        let mut attrs: u8 = 0;

        for &b in password {
            if (attrs & ALL) == ALL && (attrs & !ALL) >= (4 << SYMBOL_SHIFT) {
                return true;
            }

            if b.is_ascii_uppercase() {
                attrs |= HAS_UPPER;
            } else if b.is_ascii_lowercase() {
                attrs |= HAS_LOWER;
            } else if b.is_ascii_digit() {
                attrs |= HAS_DIGIT;
            } else if b == b'+' || b == b'/' {
                attrs += 1 << SYMBOL_SHIFT;
            }
        }

        false
    }
}

impl fmt::Display for KeyfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength => write!(
                f,
                "Referred file's size doesn't match; 128 bytes *only* allowed"
            ),
            Self::Other(other) => write!(f, "{other}"),
        }
    }
}

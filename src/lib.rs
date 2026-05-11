use std::{
    fmt,
    fs::File,
    io::{ErrorKind, Read},
    ops::Range,
    path::Path,
};

use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct Keyfile([u8; 128 + 1]);

#[derive(Debug)]
pub enum KeyfileError {
    NoSuchFile,
    IsADirectory,
    BadLength,
    Other(ErrorKind),
}

impl Keyfile {
    const HASH_RANGE: Range<usize> = 0..12;
    pub const KEY_SIZE: usize = (Self::HASH_RANGE.end - Self::HASH_RANGE.start).div_ceil(3) * 4;

    pub fn try_new<P: AsRef<Path>>(path: P) -> Result<Self, KeyfileError> {
        let mut ret = Self([0; _]);
        let mut file = File::open(path).map_err(|err| match err.kind() {
            ErrorKind::NotFound => KeyfileError::NoSuchFile,
            ErrorKind::IsADirectory => KeyfileError::IsADirectory,
            other => KeyfileError::Other(other),
        })?;

        match file.read(&mut ret.0) {
            Ok(128) => Ok(ret),
            Ok(_) => Err(KeyfileError::BadLength),
            Err(other) => Err(KeyfileError::Other(other.kind())),
        }
    }

    pub fn generate<S: AsRef<str>>(&self, seed: S, output: &mut [u8; Self::KEY_SIZE]) {
        let seed = seed.as_ref();

        let mut hasher = Sha256::new_with_prefix(&self.0[0..32]);

        for part in seed.split_whitespace() {
            hasher.update(part);
        }

        loop {
            let mut hash = hasher.clone().finalize();
            Base64::encode(&hash[Self::HASH_RANGE], output)
                .expect("`Self::KEY_SIZE` should match the encoded length for `Self::HASH_RANGE`");

            if Self::is_strong_enough(output) {
                break;
            }

            hasher.update(hash);
            hash.zeroize();
        }
    }

    fn is_strong_enough(key: &[u8; Self::KEY_SIZE]) -> bool {
        const HAS_UPPER: u8 = 1 << 0;
        const HAS_LOWER: u8 = 1 << 1;
        const HAS_DIGIT: u8 = 1 << 2;
        const ALL: u8 = HAS_UPPER | HAS_LOWER | HAS_DIGIT;
        const SYMBOL_SHIFT: u8 = 3;

        let mut flags: u8 = 0;

        for &b in key {
            if (flags & ALL) == ALL && (flags & !ALL) >= (4 << SYMBOL_SHIFT) {
                return true;
            }

            if b.is_ascii_uppercase() {
                flags |= HAS_UPPER;
            } else if b.is_ascii_lowercase() {
                flags |= HAS_LOWER;
            } else if b.is_ascii_digit() {
                flags |= HAS_DIGIT;
            } else if b == b'+' || b == b'/' {
                flags += 1 << SYMBOL_SHIFT;
            }
        }

        false
    }
}

impl fmt::Display for KeyfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            Self::NoSuchFile => "The provided path doesn't exist",
            Self::IsADirectory => "Path refers to a directory, not a file",
            Self::BadLength => "Referred file's size doesn't match; 128 bytes *only* allowed",
            Self::Other(other) => return write!(f, "{other}"),
        };
        write!(f, "{string}")
    }
}

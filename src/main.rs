use std::{
    fs::File,
    io::{self, BufRead, Read},
    path::PathBuf,
    process,
};

use clap::Parser;
use keegen::{Keyfile, KeyfileError, consts::*};
use zeroize::Zeroizing;

#[derive(Parser)]
pub struct Args {
    keyfile: PathBuf,
}

fn main() {
    let args = Args::parse();

    let mut file = match File::open(args.keyfile) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let keyfile = {
        let mut buf = Zeroizing::new([0u8; KEYFILE_LEN + 1]); // + 1 as a canary for oversized files.
        let n_read = match file.read(&mut *buf) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        };

        match TryInto::<Keyfile>::try_into(&buf[..n_read]) {
            Ok(kf) => kf,
            Err(e) => {
                match e {
                    KeyfileError::BadLength { expected } => {
                        eprintln!(
                            "Error: Keyfile has incorrect size; expected *exactly* {expected} bytes."
                        );
                    }
                }
                process::exit(1);
            }
        }
    };

    let mut seed = String::with_capacity(128);
    if let Err(e) = io::stdin().lock().read_line(&mut seed) {
        eprintln!("Error: {e}");
        process::exit(1);
    }

    let mut key = Zeroizing::new([0u8; KEY_BUF_LEN]);

    print!("{}", keyfile.gen_key(seed.trim(), &mut key));
}

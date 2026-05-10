use std::{
    io::{self, BufRead},
    path::PathBuf,
    process,
};

use clap::Parser;
use keegen::Keyfile;

#[derive(Parser)]
struct Cli {
    keyfile: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let keyfile = Keyfile::try_new(cli.keyfile).unwrap_or_else(|err| {
        eprintln!("Error: {err}");
        process::exit(1)
    });

    let mut seed = String::with_capacity(64);
    io::stdin()
        .lock()
        .read_line(&mut seed)
        .expect("Stdin should be available for reading");

    let mut key = [0; Keyfile::KEY_SIZE];
    keyfile.generate(&seed, &mut key);

    print!(
        "{}",
        str::from_utf8(&key).expect("Resulting key should be comprised of ASCII only")
    );
}

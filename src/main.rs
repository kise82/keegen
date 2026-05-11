use std::{
    fs::File,
    io::{self, BufRead},
    path::PathBuf,
    process,
};

use clap::{Parser, Subcommand};
use keegen::Keyfile;

#[derive(Parser)]
struct Cli {
    keyfile: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Extracts the symmetric key from the keyfile.
    Extract,
}

fn main() {
    let cli = Cli::parse();
    let keyfile = Keyfile::try_new(cli.keyfile).unwrap_or_else(|err| {
        eprintln!("Error: {err}");
        process::exit(1)
    });

    match cli.command {
        None => {
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
        Some(Commands::Extract) => match File::create_new("./secret.key") {
            Ok(file) => {
                if keyfile.extract_secret(file) {
                    println!("Secret written to `./secret.key`.");
                } else {
                    eprintln!("Error: Couldn't write secret to `./secret.key`.");
                }
            }
            Err(err) => {
                eprintln!("Error: Unable to create `./secret.key` -- {err}");
                process::exit(1);
            }
        },
    }
}

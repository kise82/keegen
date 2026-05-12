use std::{
    fs::File,
    io::{self, BufRead},
    path::PathBuf,
    process,
};

use clap::{Parser, Subcommand};
use keegen::Keyfile;
use rand::rngs::StdRng;
use zeroize::Zeroize;

#[derive(Parser)]
struct Cli {
    keyfile: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a new keyfile
    Generate,

    /// Extracts the symmetric key from the keyfile.
    Extract,
}

fn main() {
    let cli = Cli::parse();
    let keyfile = if let Some(&Commands::Generate) = cli.command.as_ref() {
        Keyfile::new_random(rand::make_rng::<StdRng>())
    } else {
        Keyfile::try_new(cli.keyfile.clone()).unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            process::exit(1)
        })
    };

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

            key.zeroize();
        }
        Some(Commands::Generate) => {
            if keyfile.save(cli.keyfile) {
                println!("New keyfile saved.");
            } else {
                eprintln!(
                    "\
Error: Unable to save new keyfile.
Possible reasons:
 - File with such name already exists;
 - No write permissions; or
 - An unrecoverable filesystem error."
                );
            }
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

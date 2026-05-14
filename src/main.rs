use std::{
    io::{self, BufRead},
    path::PathBuf,
    process,
    str::FromStr,
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
    /// Creates a new keyfile
    New,

    /// Extracts a 256-bit symmetric key from the keyfile.
    Extract { path: Option<PathBuf> },
}

fn main() {
    let cli = Cli::parse();
    let keyfile = if matches!(cli.command, Some(Commands::New)) {
        Keyfile::new_random(rand::make_rng::<StdRng>())
    } else {
        Keyfile::new_from_file(&cli.keyfile).unwrap_or_else(|err| {
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

            let mut password = [0; Keyfile::PW_SIZE];
            keyfile.derive_pass(&seed, &mut password);
            seed.zeroize();

            print!(
                "{}",
                str::from_utf8(&password).expect("Resulting key should be comprised of ASCII only")
            );

            password.zeroize();
        }
        Some(Commands::New) => {
            if let Err(err) = keyfile.save_to(cli.keyfile) {
                eprintln!("Error: {err}");
                process::exit(1);
            }
            println!("New keyfile written.");
        }
        Some(Commands::Extract { path }) => {
            let path = path.unwrap_or(
                PathBuf::from_str("./secret.key").expect("`./secret.key` should be a valid path"),
            );
            if let Err(err) = keyfile.extract_symm_to(&path) {
                eprintln!("Error: {err}");
                process::exit(1);
            }
            println!("Symmetric key extracted into `{}`.", path.display());
        }
    }
}

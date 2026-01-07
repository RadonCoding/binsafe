mod engine;
mod exceptions;
mod protections;

use clap::Parser;
use logger::info;
use std::{fs, path::PathBuf};

use crate::{
    engine::Engine,
    protections::{mutation::Mutation, virtualization::Virtualization},
};

#[derive(Parser)]
#[command(author, version)]
struct Args {
    input: PathBuf,

    #[arg(short = 'v', long = "virtualize")]
    virtualize: bool,

    #[arg(short = 'm', long = "mutate")]
    mutate: bool,
}

fn main() {
    let args = Args::parse();

    let input = &args.input;

    let mut engine = Engine::new(input);

    engine.scan();

    if args.virtualize {
        engine.apply::<Virtualization>();
    }

    if args.mutate {
        engine.apply::<Mutation>();
    }

    let protected = engine.execute();

    let output = if let Some(extension) = input.extension() {
        input.with_extension("").with_file_name(format!(
            "{}.protected.{}",
            input.file_stem().unwrap().to_str().unwrap(),
            extension.to_str().unwrap()
        ))
    } else {
        let mut output = input.to_path_buf();
        output.set_file_name(format!(
            "{}.protected",
            input.file_name().unwrap().to_str().unwrap()
        ));
        output
    };

    fs::write(&output, protected).unwrap();

    info!("Wrote output to '{}'", output.display());
}

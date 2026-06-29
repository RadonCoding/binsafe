use clap::Parser;
use logger::info;
use std::fs;

use obfuscator::{args::Args, engine::Engine, protections::virtualization::Virtualization};

fn main() {
    let args = Args::parse();

    let mut engine = Engine::new(&args);

    engine.scan();

    if args.virtualization {
        engine.apply::<Virtualization>();
    }

    let protected = engine.execute();

    let output = if let Some(extension) = args.input.extension() {
        args.input.with_extension("").with_file_name(format!(
            "{}.protected.{}",
            args.input.file_stem().unwrap().to_str().unwrap(),
            extension.to_str().unwrap()
        ))
    } else {
        let mut output = args.input.to_path_buf();
        output.set_file_name(format!(
            "{}.protected",
            args.input.file_name().unwrap().to_str().unwrap()
        ));
        output
    };

    fs::write(&output, protected).unwrap();

    info!("Wrote output to '{}'", output.display());
}

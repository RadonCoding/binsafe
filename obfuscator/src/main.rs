mod engine;
mod protections;

use std::{env, fs, path::Path};

use logger::info;

use crate::{
    engine::Engine,
    protections::{mutation::Mutation, virtualization::Virtualization},
};

fn main() {
    let args = env::args().collect::<Vec<String>>();

    let input = Path::new(&args[1]);

    let mut engine = Engine::new(input);

    engine.scan();

    engine.apply::<Virtualization>();
    engine.apply::<Mutation>();

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

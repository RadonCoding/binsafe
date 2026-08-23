use std::{env, fs, path::PathBuf};

include!("src/lib.rs");

fn bytes_to_csv(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<String>>()
        .join(", ")
}

fn main() {
    println!("cargo:rerun-if-env-changed=OUTPUT_DIRECTORY");
    println!("cargo:rerun-if-env-changed=TEMPLATES_DIRECTORY");

    let (Ok(output), Ok(templates)) = (
        env::var("OUTPUT_DIRECTORY"),
        env::var("TEMPLATES_DIRECTORY"),
    ) else {
        return;
    };

    let output = PathBuf::from(output);
    let templates = PathBuf::from(templates);

    let begin = bytes_to_csv(&MARKER_BEGIN);
    let end = bytes_to_csv(&MARKER_END);

    fs::create_dir_all(&output).unwrap();

    for entry in fs::read_dir(&templates).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let content = fs::read_to_string(&path).unwrap();
        fs::write(
            output.join(path.file_name().unwrap()),
            content.replace("{begin}", &begin).replace("{end}", &end),
        )
        .unwrap();
    }
}

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(author, version)]
pub struct Args {
    pub input: PathBuf,

    #[arg(short = 'v', long = "virtualization")]
    pub virtualization: bool,
}

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(author, version)]
pub struct Args {
    pub input: PathBuf,

    #[arg(long = "virtualization")]
    pub virtualization: bool,

    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

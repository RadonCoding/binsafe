use std::path::PathBuf;

use clap::{ArgAction, Parser};

#[derive(Parser)]
#[command(author, version)]
pub struct Args {
    pub input: PathBuf,

    #[arg(short = 'v', long = "virtualization")]
    pub virtualization: bool,

    #[arg(short = 'a', long = "attestation", default_value_t = true, action = ArgAction::Set)]
    pub attestation: bool,

    #[arg(short = 'm', long = "mutation")]
    pub mutation: bool,
}

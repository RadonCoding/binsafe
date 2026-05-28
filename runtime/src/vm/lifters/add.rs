use iced_x86::Instruction;

use crate::vm::encoders::{add::Add, Encode};
use crate::vm::lifters::arithmetic::{self, Tail};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    arithmetic::encode(instruction, |width| Add { width }, Tail::Writeback)
}

use std::rc::Rc;
use iced_x86::Instruction;

use crate::vm::encoders::{and::And, Encode};
use crate::vm::lifters::arithmetic::{self, Tail};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    arithmetic::encode(instruction, |width| And { width }, Tail::Writeback)
}

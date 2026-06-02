use std::rc::Rc;
use iced_x86::Instruction;

use crate::vm::encoders::{xor::Xor, Encode};
use crate::vm::lifters::unary;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    unary::encode(instruction, u64::MAX, false, true, |width| Xor { width })
}

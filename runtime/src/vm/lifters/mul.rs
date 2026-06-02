use std::rc::Rc;
use iced_x86::Instruction;

use crate::vm::encoders::{mul::Mul, Encode};
use crate::vm::lifters::multiply;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    multiply::wide(instruction, |width| Mul { width })
}

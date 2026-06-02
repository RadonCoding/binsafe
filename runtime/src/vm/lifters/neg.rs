use std::rc::Rc;
use iced_x86::Instruction;

use crate::vm::encoders::{sub::Sub, Encode};
use crate::vm::lifters::unary;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    unary::encode(instruction, 0, true, false, |width| Sub { width })
}

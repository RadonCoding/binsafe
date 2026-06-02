use std::rc::Rc;
use iced_x86::Instruction;

use crate::vm::encoders::{imul::Imul, Encode};
use crate::vm::lifters::multiply;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    if instruction.op_count() == 1 {
        multiply::wide(instruction, |width| Imul { width })
    } else {
        multiply::narrow(instruction)
    }
}

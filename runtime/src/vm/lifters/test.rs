use std::rc::Rc;
use iced_x86::Instruction;

use crate::vm::encoders::{test::Test, Encode};
use crate::vm::lifters::arithmetic::{self, Tail};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    arithmetic::encode(instruction, |width| Test { width }, Tail::Discard)
}

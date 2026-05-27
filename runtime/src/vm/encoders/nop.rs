use iced_x86::{Code, Instruction};

use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Nop;

impl Encode for Nop {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Nop)]
    }
}

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    match instruction.code() {
        Code::Nopw | Code::Nopd | Code::Nopq | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 => {
            Some(vec![Box::new(Nop)])
        }
        _ => None,
    }
}

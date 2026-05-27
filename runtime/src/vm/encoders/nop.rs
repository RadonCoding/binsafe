use iced_x86::{Code, Instruction};

use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;

pub struct Nop;

impl Encode for Nop {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Nop)]
    }
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    match instruction.code() {
        Code::Nopw | Code::Nopd | Code::Nopq | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 => {
            Some(Nop.encode(mapper))
        }
        _ => None,
    }
}

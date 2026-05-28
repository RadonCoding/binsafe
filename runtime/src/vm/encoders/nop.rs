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

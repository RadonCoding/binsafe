use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct LoadMemory {
    pub width: VMWidth,
}

impl Encode for LoadMemory {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::LoadMemory), mapper.index(self.width)]
    }
}

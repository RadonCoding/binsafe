use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct StoreMemory {
    pub width: VMWidth,
}

impl Encode for StoreMemory {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::StoreMemory), mapper.index(self.width)]
    }
}

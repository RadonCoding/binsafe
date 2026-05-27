use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMOp};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct StoreMem {
    pub width: VMBits,
}

impl Encode for StoreMem {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::StoreMem), mapper.index(self.width)]
    }
}

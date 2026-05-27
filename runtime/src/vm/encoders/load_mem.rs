use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMOp};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct LoadMem {
    pub width: VMBits,
}

impl Encode for LoadMem {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::LoadMem), mapper.index(self.width)]
    }
}

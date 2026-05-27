use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMOp};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct LoadImm {
    pub width: VMBits,
    pub source: Vec<u8>,
}

impl Encode for LoadImm {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::LoadImm), mapper.index(self.width)];
        bytes.extend_from_slice(&self.source);
        bytes
    }
}

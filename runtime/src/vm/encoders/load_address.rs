use crate::mapper::Mapper;
use crate::vm::bytecode::{VMMem, VMOp};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct LoadAddress {
    pub source: VMMem,
}

impl Encode for LoadAddress {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::LoadAddress)];
        bytes.extend(self.source.encode(mapper));
        bytes
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMMem, VMOp};
use crate::vm::encoders::{Effect, Encode};

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

    fn reads(&self) -> Vec<Effect> {
        vec![
            Effect::Register(self.source.base),
            Effect::Register(self.source.index),
        ]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch]
    }
}

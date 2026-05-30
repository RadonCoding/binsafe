use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct StoreMemory {
    pub width: VMWidth,
}

impl Encode for StoreMemory {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::StoreMemory), mapper.index(self.width)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch, Effect::Scratch]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![Effect::Memory]
    }
}

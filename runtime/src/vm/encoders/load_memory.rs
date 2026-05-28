use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct LoadMemory {
    pub width: VMWidth,
}

impl Encode for LoadMemory {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::LoadMemory), mapper.index(self.width)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![Effect::Scratch]
    }
}

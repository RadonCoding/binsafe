use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Add {
    pub width: VMWidth,
}

impl Encode for Add {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Add), mapper.index(self.width)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch, Effect::Scratch]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Flags, Effect::Scratch]
    }
}

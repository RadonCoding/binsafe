use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Xor{
    pub width: VMWidth,
}

impl Encode for Xor {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Xor), mapper.index(self.width)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Flags]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

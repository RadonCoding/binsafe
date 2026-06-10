use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Exchange {
    pub width: VMWidth,
}

impl Encode for Exchange {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Exchange), mapper.index(self.width)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Memory]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

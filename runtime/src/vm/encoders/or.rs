use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Or{
    pub width: VMWidth,
}

impl Encode for Or {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Or), mapper.index(self.width)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Flags]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Divide {
    pub width: VMWidth,
}

impl Encode for Divide {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Div), mapper.index(self.width)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

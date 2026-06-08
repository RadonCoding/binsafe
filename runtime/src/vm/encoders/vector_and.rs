use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct VectorAnd {
    pub width: VMWidth,
}

impl Encode for VectorAnd {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::VectorAnd), mapper.index(self.width)]
    }

    fn depth(&self) -> i32 {
        -self.width.slots()
    }
}

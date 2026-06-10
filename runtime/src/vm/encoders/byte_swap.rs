use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct ByteSwap {
    pub width: VMWidth,
}

impl Encode for ByteSwap {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::ByteSwap), mapper.index(self.width)]
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct PackedByteMask {
    pub width: VMWidth,
}

impl Encode for PackedByteMask {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::PackedByteMask), mapper.index(self.width)]
    }

    fn depth(&self) -> i32 {
        1 - self.width.slots()
    }
}

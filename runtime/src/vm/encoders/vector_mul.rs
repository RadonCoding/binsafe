use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMPrecision, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct VectorMul {
    pub width: VMWidth,
    pub stride: VMWidth,
    pub precision: VMPrecision,
}

impl Encode for VectorMul {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::VectorMul),
            mapper.index(self.width),
            mapper.index(self.stride),
            mapper.index(self.precision),
        ]
    }

    fn depth(&self) -> i32 {
        -self.width.slots()
    }
}

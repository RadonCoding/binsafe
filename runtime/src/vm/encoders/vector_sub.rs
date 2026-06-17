use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMPrecision, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct VectorSub {
    pub width: VMWidth,
    pub stride: VMWidth,
    pub precision: VMPrecision,
}

impl Encode for VectorSub {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::VectorSub),
            mapper.index(self.width),
            mapper.index(self.stride),
            mapper.index(self.precision),
        ]
    }

    fn depth(&self) -> i32 {
        -self.width.slots()
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMPrecision, VMWidth};
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct VectorAdd {
    pub width: VMWidth,
    pub stride: VMWidth,
    pub precision: VMPrecision,
}

impl Encode for VectorAdd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::VectorAdd)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(self.width),
            mapper.index(self.stride),
            mapper.index(self.precision),
        ]
    }

    fn consumes(&self) -> i32 {
        2
    }

    fn produces(&self) -> i32 {
        1
    }

}

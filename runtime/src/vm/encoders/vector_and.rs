use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct VectorAnd {
    pub width: VMWidth,
}

impl Encode for VectorAnd {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::VectorAnd)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.width)]
    }

    fn consumes(&self) -> i32 {
        2
    }

    fn produces(&self) -> i32 {
        1
    }

}

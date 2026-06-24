use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct PackedByteMask {
    pub width: VMWidth,
}

impl Encode for PackedByteMask {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::PackedByteMask), mapper.index(self.width)]
    }

    fn depth(&self) -> i32 {
        1 - self.width.slots()
    }
}

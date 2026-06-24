use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct PackedByteEqual {
    pub width: VMWidth,
}

impl Encode for PackedByteEqual {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::PackedByteEqual),
            mapper.index(self.width),
        ]
    }

    fn depth(&self) -> i32 {
        -self.width.slots()
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCode, VMWidth};
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

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::PackedByteMask)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.width)]
    }

    fn consumes(&self) -> i32 {
        1
    }

    fn produces(&self) -> i32 {
        1
    }
}

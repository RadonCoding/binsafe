use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct LoadMemory {
    pub width: VMWidth,
}

impl Encode for LoadMemory {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::LoadMemory)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.width)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Memory]
    }

    fn consumes(&self) -> i32 {
        1
    }

    fn produces(&self) -> i32 {
        1
    }
}

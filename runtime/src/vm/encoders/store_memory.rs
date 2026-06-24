use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct StoreMemory {
    pub width: VMWidth,
}

impl Encode for StoreMemory {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::StoreMemory), mapper.index(self.width)]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![Effect::Memory]
    }

    fn depth(&self) -> i32 {
        -(self.width.slots() + 1)
    }
}

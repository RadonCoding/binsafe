use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMVec, VMWidth};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct StoreExtend {
    pub width: VMWidth,
    pub destination: VMVec,
}

impl Encode for StoreExtend {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::StoreExtend),
            mapper.index(self.width),
            mapper.index(self.destination),
        ]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Vector(self.destination)]
    }

    fn depth(&self) -> i32 {
        -self.width.slots()
    }
}

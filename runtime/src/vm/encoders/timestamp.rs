use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct Timestamp;

impl Encode for Timestamp {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Timestamp)]
    }

    fn depth(&self) -> i32 {
        2
    }
}

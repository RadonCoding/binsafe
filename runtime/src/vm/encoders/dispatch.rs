use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct Dispatch {
    pub operation: Box<dyn Encode>,
}

impl Encode for Dispatch {
    fn as_any(&self) -> &dyn Any {
        self.operation.as_any()
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self.operation.as_any_mut()
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::Dispatch)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        self.operation.encode(mapper)
    }

    fn size(&self, mapper: &mut Mapper) -> usize {
        self.operation.size(mapper)
    }

    fn reads(&self) -> Vec<Effect> {
        self.operation.reads()
    }

    fn writes(&self) -> Vec<Effect> {
        self.operation.writes()
    }

    fn consumes(&self) -> i32 {
        1 + self.operation.consumes()
    }

    fn produces(&self) -> i32 {
        self.operation.produces()
    }

    fn is_source(&self) -> bool {
        self.operation.is_source()
    }

    fn is_destination(&self) -> bool {
        self.operation.is_destination()
    }

    fn is_branch(&self) -> bool {
        self.operation.is_branch()
    }

    fn children_ref(&self) -> Option<&[Box<dyn Encode>]> {
        self.operation.children_ref()
    }

    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Encode>>> {
        self.operation.children_mut()
    }

    fn seal(&mut self, mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8], usize)) {
        self.operation.seal(mapper, transform);
    }
}

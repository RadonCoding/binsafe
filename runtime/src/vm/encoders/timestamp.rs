use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;
use std::any::Any;
use std::fmt::{Debug, Formatter, Result};

pub struct Timestamp {
    _marker: u8,
}

impl Timestamp {
    pub fn new() -> Self {
        Self { _marker: 0 }
    }
}

impl Debug for Timestamp {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct(self.name()).finish()
    }
}

impl Encode for Timestamp {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::Timestamp)
    }

    fn encode(&self, _mapper: &mut Mapper) -> Vec<u8> {
        vec![]
    }

    fn consumes(&self) -> i32 {
        0
    }

    fn produces(&self) -> i32 {
        2
    }
}

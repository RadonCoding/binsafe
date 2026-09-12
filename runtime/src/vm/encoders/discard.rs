use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;
use std::any::Any;
use std::fmt::{Debug, Formatter, Result};

pub struct Discard {
    _marker: u8,
}

impl Discard {
    pub fn new() -> Self {
        Self { _marker: 0 }
    }
}

impl Debug for Discard {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct(self.name()).finish()
    }
}

impl Encode for Discard {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::Discard)
    }

    fn encode(&self, _mapper: &mut Mapper) -> Vec<u8> {
        vec![]
    }

    fn consumes(&self) -> i32 {
        1
    }

    fn produces(&self) -> i32 {
        0
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;
use std::fmt::{Debug, Formatter, Result};

pub struct Pop {
    _marker: u8,
}

impl Pop {
    pub fn new() -> Self {
        Self { _marker: 0 }
    }
}

impl Debug for Pop {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct(self.name()).finish()
    }
}

impl Encode for Pop {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Pop)]
    }

    fn reads(&self) -> Vec<Effect> {
        vec![Effect::Memory, Effect::Register(VMReg::Rsp)]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![Effect::Register(VMReg::Rsp)]
    }

    fn depth(&self) -> i32 {
        1
    }
}

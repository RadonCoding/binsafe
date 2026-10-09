use crate::mapper::Mapper;
use crate::vm::bytecode::VMCode;
use crate::vm::encoders::Encode;
use std::any::Any;
use std::fmt::{Debug, Formatter, Result};

pub struct Cpuid {
    _marker: u8,
}

impl Cpuid {
    pub fn new() -> Self {
        Self { _marker: 0 }
    }
}

impl Debug for Cpuid {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct(self.name()).finish()
    }
}

impl Encode for Cpuid {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::Cpuid)
    }

    fn encode(&self, _mapper: &mut Mapper) -> Vec<u8> {
        vec![]
    }

    fn consumes(&self) -> i32 {
        2
    }

    fn produces(&self) -> i32 {
        4
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct LoadRegister {
    pub width: VMWidth,
    pub source: VMReg,
}

impl Encode for LoadRegister {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::LoadRegister)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.width), mapper.index(self.source)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Register(self.source)]
    }

    fn consumes(&self) -> i32 {
        0
    }

    fn produces(&self) -> i32 {
        1
    }
}

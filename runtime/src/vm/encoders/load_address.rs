use crate::mapper::Mapper;
use crate::vm::bytecode::{VMMem, VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct LoadAddress {
    pub source: VMMem,
}

impl Encode for LoadAddress {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::LoadAddress)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        self.source.encode(mapper)
    }

    fn reads(&self) -> Vec<Effect> {
        vec![
            Effect::Register(self.source.base),
            Effect::Register(self.source.index),
            Effect::Register(VMReg::VImmAdd),
            Effect::Register(VMReg::VImmMul),
        ]
    }

    fn consumes(&self) -> i32 {
        0
    }

    fn produces(&self) -> i32 {
        1
    }
}

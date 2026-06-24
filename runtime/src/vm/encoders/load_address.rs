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

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::LoadAddress)];
        bytes.extend(self.source.encode(mapper));
        bytes
    }

    fn reads(&self) -> Vec<Effect> {
        vec![
            Effect::Register(self.source.base),
            Effect::Register(self.source.index),
            Effect::Register(VMReg::VImm),
        ]
    }

    fn depth(&self) -> i32 {
        1
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMMem, VMCode, VMReg};
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

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::LoadAddress)
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

    fn seal(&mut self, _mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8], usize)) {
        let mut displacement = self.source.displacement.to_le_bytes();
        transform(&mut displacement, 0);
        self.source.displacement = i32::from_le_bytes(displacement);
    }
}

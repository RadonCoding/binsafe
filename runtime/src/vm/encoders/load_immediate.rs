use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCode, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct LoadImmediate {
    pub width: VMWidth,
    pub source: Vec<u8>,
}

impl Encode for LoadImmediate {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::LoadImmediate)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(self.width)];
        bytes.extend_from_slice(&self.source);
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![
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
        transform(&mut self.source, 0);
    }
}

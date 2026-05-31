use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct LoadImmediate {
    pub width: VMWidth,
    pub source: Vec<u8>,
}

impl Encode for LoadImmediate {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::LoadImmediate), mapper.index(self.width)];
        bytes.extend_from_slice(&self.source);
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::VImm)]
    }

    fn depth(&self) -> i32 {
        1
    }
}

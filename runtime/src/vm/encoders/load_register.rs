use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct LoadRegister {
    pub width: VMWidth,
    pub source: VMReg,
}

impl Encode for LoadRegister {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::LoadRegister),
            mapper.index(self.width),
            mapper.index(self.source),
        ]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Reg(self.source)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch]
    }
}

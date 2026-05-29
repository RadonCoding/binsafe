use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct StoreRegister {
    pub width: VMWidth,
    pub destination: VMReg,
}

impl Encode for StoreRegister {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::StoreRegister),
            mapper.index(self.width),
            mapper.index(self.destination),
        ]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Register(self.destination)]
    }
}

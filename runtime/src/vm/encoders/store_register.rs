use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct StoreRegister {
    pub width: VMWidth,
    pub destination: VMReg,
}

impl Encode for StoreRegister {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::StoreRegister),
            mapper.index(self.width),
            mapper.index(self.destination),
        ]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Register(self.destination)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

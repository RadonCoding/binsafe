use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Rol {
    pub width: VMWidth,
}

impl Encode for Rol {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Rol), mapper.index(self.width)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::Flags)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

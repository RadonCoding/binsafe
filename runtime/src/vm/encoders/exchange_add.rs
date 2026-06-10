use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct ExchangeAdd {
    pub width: VMWidth,
}

impl Encode for ExchangeAdd {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::ExchangeAdd), mapper.index(self.width)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Memory, Effect::Register(VMReg::Flags)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

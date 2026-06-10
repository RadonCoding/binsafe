use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct SubBorrow {
    pub width: VMWidth,
}

impl Encode for SubBorrow {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::SubBorrow), mapper.index(self.width)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::Flags)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::Flags)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

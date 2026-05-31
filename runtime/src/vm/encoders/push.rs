use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Push;

impl Encode for Push {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Push)]
    }

    fn reads(&self) -> Vec<Effect> {
        vec![Effect::Register(VMReg::Rsp)]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![Effect::Memory, Effect::Register(VMReg::Rsp)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct Ret;

impl Encode for Ret {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Ret)]
    }

    fn reads(&self) -> Vec<Effect> {
        vec![Effect::Register(VMReg::Rsp)]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![
            Effect::Register(VMReg::Rsp),
            Effect::Register(VMReg::NBranch),
        ]
    }

    fn depth(&self) -> i32 {
        -1
    }

    fn branches(&self) -> bool {
        true
    }
}

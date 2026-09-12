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

    fn op(&self) -> Option<VMOp> {
        Some(VMOp::Ret)
    }

    fn encode(&self, _mapper: &mut Mapper) -> Vec<u8> {
        vec![]
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

    fn consumes(&self) -> i32 {
        1
    }

    fn produces(&self) -> i32 {
        0
    }

    fn is_branch(&self) -> bool {
        true
    }
}

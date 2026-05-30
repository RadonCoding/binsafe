use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Discard;

impl Encode for Discard {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Discard)]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Scratch]
    }
}

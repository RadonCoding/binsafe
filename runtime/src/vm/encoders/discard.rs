use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Discard;

impl Encode for Discard {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Discard)]
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Pcmpeqb;

impl Encode for Pcmpeqb {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Pcmpeqb)]
    }

    fn depth(&self) -> i32 {
        -2
    }
}

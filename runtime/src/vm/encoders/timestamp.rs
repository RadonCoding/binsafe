use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Timestamp;

impl Encode for Timestamp {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Timestamp)]
    }

    fn depth(&self) -> i32 {
        2
    }
}

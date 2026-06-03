use crate::mapper::Mapper;
use crate::vm::bytecode::VMOp;
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Pmovmskb;

impl Encode for Pmovmskb {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Pmovmskb)]
    }

    fn depth(&self) -> i32 {
        -1
    }
}

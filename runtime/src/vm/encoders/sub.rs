use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Sub {
    pub width: VMWidth,
}

impl Encode for Sub {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::Sub), mapper.index(self.width)]
    }
}

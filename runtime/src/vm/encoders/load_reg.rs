use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMOp, VMReg};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct LoadReg {
    pub width: VMBits,
    pub source: VMReg,
}

impl Encode for LoadReg {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::LoadReg),
            mapper.index(self.width),
            mapper.index(self.source),
        ]
    }
}

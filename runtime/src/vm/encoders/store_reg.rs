use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMOp, VMReg};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct StoreReg {
    pub width: VMBits,
    pub destination: VMReg,
}

impl Encode for StoreReg {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::StoreReg),
            mapper.index(self.width),
            mapper.index(self.destination),
        ]
    }
}

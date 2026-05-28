use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg, VMWidth};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct StoreRegister {
    pub width: VMWidth,
    pub destination: VMReg,
}

impl Encode for StoreRegister {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::StoreRegister),
            mapper.index(self.width),
            mapper.index(self.destination),
        ]
    }
}

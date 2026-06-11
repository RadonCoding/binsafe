use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMVec, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct StoreExtend {
    pub width: VMWidth,
    pub destination: VMVec,
}

impl Encode for StoreExtend {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::StoreExtend),
            mapper.index(self.width),
            mapper.index(self.destination),
        ]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Vector(self.destination)]
    }

    fn depth(&self) -> i32 {
        -self.width.slots()
    }
}

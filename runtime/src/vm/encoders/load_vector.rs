use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMVec, VMWidth};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct LoadVector {
    pub width: VMWidth,
    pub source: VMVec,
}

impl Encode for LoadVector {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::LoadVector),
            mapper.index(self.width),
            mapper.index(self.source),
        ]
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Vector(self.source)]
    }

    fn depth(&self) -> i32 {
        self.width.slots()
    }
}

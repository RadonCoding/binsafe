use crate::runtime::Runtime;
use crate::vm::bytecode::{VMCode, VMPrecision, VMWidth};
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct VectorSub {
    pub width: VMWidth,
    pub stride: VMWidth,
    pub precision: VMPrecision,
}

impl Encode for VectorSub {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::VectorSub)
    }

    fn encode(&self, rt: &mut Runtime) -> Vec<u8> {
        vec![
            rt.mapper.index(self.width),
            rt.mapper.index(self.stride),
            rt.mapper.index(self.precision),
        ]
    }

    fn consumes(&self) -> i32 {
        2
    }

    fn produces(&self) -> i32 {
        1
    }
}

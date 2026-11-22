use crate::runtime::Runtime;
use crate::vm::bytecode::{VMCode, VMWidth};
use crate::vm::encoders::Encode;
use std::any::Any;

#[derive(Debug)]
pub struct Div {
    pub width: VMWidth,
}

impl Encode for Div {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::Div)
    }

    fn encode(&self, rt: &mut Runtime) -> Vec<u8> {
        vec![rt.mapper.index(self.width)]
    }

    fn consumes(&self) -> i32 {
        3
    }

    fn produces(&self) -> i32 {
        2
    }
}

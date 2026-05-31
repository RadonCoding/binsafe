use std::any::Any;
use std::fmt::Debug;
use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMReg, VMWidth};

#[cfg(debug_assertions)]
mod debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Effect {
    Register(VMReg),
    Memory,
}

pub trait Encode: Debug + Any {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8>;

    fn size(&self, mapper: &mut Mapper) -> usize {
        self.encode(mapper).len()
    }

    fn reads(&self) -> Vec<Effect> {
        vec![]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![]
    }

    fn depth(&self) -> i32 {
        0
    }

    fn branches(&self) -> bool {
        false
    }

    fn children(&mut self) -> Option<&mut Vec<Rc<dyn Encode>>> {
        None
    }
}

pub fn encode_immediate(value: u64) -> (VMWidth, usize) {
    match value {
        0..=0xFF => (VMWidth::Lower8, 1),
        0..=0xFFFF => (VMWidth::Lower16, 2),
        0..=0xFFFFFFFF => (VMWidth::Lower32, 4),
        _ => (VMWidth::Lower64, 8),
    }
}

pub mod add;
pub mod and;
pub mod discard;
pub mod jcc;
pub mod load_address;
pub mod load_immediate;
pub mod load_memory;
pub mod load_register;
pub mod or;
pub mod pop;
pub mod push;
pub mod ret;
pub mod skip;
pub mod store_memory;
pub mod store_register;
pub mod sub;
pub mod test;
pub mod xor;

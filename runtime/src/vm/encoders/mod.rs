use std::any::Any;
use std::fmt::Debug;
use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMReg, VMVec};

#[cfg(debug_assertions)]
mod debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Effect {
    Register(VMReg),
    Vector(VMVec),
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

    fn seal(&mut self, _mapper: &mut Mapper, _transform: &mut dyn FnMut(&mut [u8])) {}
}

pub mod add;
pub mod add_carry;
pub mod and;
pub mod bit_scan_reverse;
pub mod bit_test;
pub mod bit_test_complement;
pub mod bit_test_reset;
pub mod bit_test_set;
pub mod byte_swap;
pub mod chain;
pub mod compare_exchange;
pub mod discard;
pub mod divide;
pub mod exchange;
pub mod exchange_add;
pub mod jcc;
pub mod load_address;
pub mod load_immediate;
pub mod load_memory;
pub mod load_register;
pub mod load_vector;
pub mod mul;
pub mod or;
pub mod packed_byte_equal;
pub mod packed_byte_mask;
pub mod pop;
pub mod push;
pub mod ret;
pub mod rol;
pub mod ror;
pub mod sar;
pub mod shl;
pub mod shr;
pub mod skip;
pub mod store_extend;
pub mod store_memory;
pub mod store_merge;
pub mod store_register;
pub mod sub;
pub mod sub_borrow;
pub mod test;
pub mod trailing_zeros;
pub mod vector_add;
pub mod vector_and;
pub mod vector_and_not;
pub mod vector_div;
pub mod vector_mul;
pub mod vector_or;
pub mod vector_sub;
pub mod vector_xor;
pub mod xor;

use iced_x86::Instruction;
use std::rc::Rc;

use crate::vm::bytecode::{VMReg, VMVec, VMWidth};
use crate::vm::encoders::{
    load_vector::LoadVector, packed_byte_mask::PackedByteMask, store_register::StoreRegister,
    Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let destination = VMReg::from(instruction.op0_register());
    let source = VMVec::from(instruction.op1_register());

    Some(vec![
        Rc::new(LoadVector {
            width: VMWidth::Lower128,
            source,
        }),
        Rc::new(PackedByteMask {
            width: VMWidth::Lower128,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower32,
            destination,
        }),
    ])
}

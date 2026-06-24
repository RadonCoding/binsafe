use iced_x86::Instruction;


use crate::vm::bytecode::{VMReg, VMVec, VMWidth};
use crate::vm::encoders::{
    load_vector::LoadVector, packed_byte_mask::PackedByteMask, store_register::StoreRegister,
    Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let destination_register = VMReg::from(instruction.op0_register());
    let source_vector = VMVec::from(instruction.op1_register());

    Some(vec![
        Box::new(LoadVector {
            width: VMWidth::Lower128,
            source: source_vector,
        }),
        Box::new(PackedByteMask {
            width: VMWidth::Lower128,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: destination_register,
        }),
    ])
}

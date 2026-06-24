use iced_x86::Instruction;

use crate::vm::bytecode::VMReg;
use crate::vm::encoders::{
    byte_swap::ByteSwap, load_register::LoadRegister, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let destination_width = operation_width(instruction, 0);
    let destination_register = VMReg::from(instruction.op0_register());

    Some(vec![
        Box::new(LoadRegister {
            width: destination_width,
            source: destination_register,
        }),
        Box::new(ByteSwap {
            width: destination_width,
        }),
        Box::new(StoreRegister {
            width: destination_width,
            destination: destination_register,
        }),
    ])
}

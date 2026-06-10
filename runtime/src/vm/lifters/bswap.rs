use iced_x86::Instruction;
use std::rc::Rc;

use crate::vm::bytecode::VMReg;
use crate::vm::encoders::{
    byte_swap::ByteSwap, load_register::LoadRegister, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let destination_width = operation_width(instruction, instruction.op0_kind());
    let destination_register = VMReg::from(instruction.op0_register());

    Some(vec![
        Rc::new(LoadRegister {
            width: destination_width,
            source: destination_register,
        }),
        Rc::new(ByteSwap {
            width: destination_width,
        }),
        Rc::new(StoreRegister {
            width: destination_width,
            destination: destination_register,
        }),
    ])
}

use std::rc::Rc;
use iced_x86::{Code, Instruction};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{load_address::LoadAddress, store_register::StoreRegister, Encode};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let destination_width = match instruction.code() {
        Code::Lea_r64_m => VMWidth::Lower64,
        Code::Lea_r32_m => VMWidth::Lower32,
        Code::Lea_r16_m => VMWidth::Lower16,
        _ => return None,
    };

    let destination_register = VMReg::from(instruction.op0_register());

    Some(vec![
        Rc::new(LoadAddress {
            source: VMMem::from(instruction),
        }),
        Rc::new(StoreRegister {
            width: destination_width,
            destination: destination_register,
        }),
    ])
}

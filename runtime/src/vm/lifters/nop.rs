use iced_x86::{Code, Instruction};

use crate::vm::encoders::{nop::Nop, Encode};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    match instruction.code() {
        Code::Nopw | Code::Nopd | Code::Nopq | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 => {
            Some(vec![Box::new(Nop)])
        }
        _ => None,
    }
}

use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::{store_register::StoreRegister, timestamp::Timestamp, Encode};
use iced_x86::Instruction;


pub fn encode(_instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    Some(vec![
        Box::new(Timestamp),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rdx,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rax,
        }),
    ])
}

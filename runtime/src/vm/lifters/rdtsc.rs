use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::{store_register::StoreRegister, timestamp::Timestamp, Encode};
use iced_x86::Instruction;
use std::rc::Rc;

pub fn encode(_instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    Some(vec![
        Rc::new(Timestamp),
        Rc::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rdx,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rax,
        }),
    ])
}

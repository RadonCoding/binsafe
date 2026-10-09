use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::{
    cpuid::Cpuid, load_register::LoadRegister, store_register::StoreRegister, Encode,
};
use iced_x86::Instruction;

pub fn encode(_instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    Some(vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower32,
            source: VMReg::Rax,
        }),
        Box::new(LoadRegister {
            width: VMWidth::Lower32,
            source: VMReg::Rcx,
        }),
        Box::new(Cpuid::new()),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rdx,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rcx,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rbx,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower32,
            destination: VMReg::Rax,
        }),
    ])
}
